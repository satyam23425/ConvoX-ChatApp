const path = require("path");
const http = require("http");
const crypto = require("crypto");
const express = require("express");
const { Server } = require("socket.io");

const port = 3000;

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  maxHttpBufferSize: 5e6,
});

app.use(express.static(path.join(__dirname, "public")));

const CHANNELS = ["general", "random", "dev", "design"];

const accounts = new Map();
const byId = new Map();
const byName = new Map();

const history = Object.fromEntries(
  CHANNELS.map((channel) => [channel, []])
);

let seq = 0;

// =========================
// PASSWORD FUNCTIONS
// =========================

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString("hex")
) {
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return {
    salt,
    hash,
  };
}

function verifyPassword(password, account) {
  const derived = crypto
    .scryptSync(password, account.salt, 64)
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(derived, "hex"),
    Buffer.from(account.hash, "hex")
  );
}

// =========================
// VALIDATION
// =========================

function validName(name) {
  return (
    typeof name === "string" &&
    /^[a-zA-Z0-9_]{3,20}$/.test(name)
  );
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6 &&
    password.length <= 72
  );
}

// =========================
// USERS
// =========================

function publicUsers() {
  return [...byId.values()].map(({ id, name, status }) => ({
    id,
    name,
    status,
  }));
}

// =========================
// AUTH RESPONSE
// =========================

function authPayload(name) {
  return {
    ok: true,
    name,
    channels: CHANNELS,
    history,
    users: publicUsers(),
  };
}

// =========================
// RESOLVE TARGET
// =========================

function resolve(user, to) {
  if (typeof to !== "string") {
    return null;
  }

  // CHANNEL
  if (to.startsWith("ch:")) {
    const channel = to.slice(3);

    if (!CHANNELS.includes(channel)) {
      return null;
    }

    return {
      type: "ch",
      room: `ch:${channel}`,
      ch: channel,
    };
  }

  // PRIVATE MESSAGE
  if (to.startsWith("dm:")) {
    const peerName = to.slice(3).toLowerCase();

    const peer = byName.get(peerName);

    if (!peer) {
      return null;
    }

    return {
      type: "dm",
      peer,
    };
  }

  return null;
}

// =========================
// SOCKET CONNECTION
// =========================

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  // =========================
  // SIGNUP
  // =========================

  socket.on(
    "signup",
    ({ name, password } = {}, ack = () => {}) => {
      name =
        typeof name === "string"
          ? name.trim()
          : "";

      if (!validName(name)) {
        return ack({
          ok: false,
          error:
            "Username must be 3–20 characters using letters, numbers or _.",
        });
      }

      if (!validPassword(password)) {
        return ack({
          ok: false,
          error:
            "Password must contain at least 6 characters.",
        });
      }

      const username = name.toLowerCase();

      if (accounts.has(username)) {
        return ack({
          ok: false,
          error: "That username is already registered.",
        });
      }

      if (byName.has(username)) {
        return ack({
          ok: false,
          error: "That username is currently active.",
        });
      }

      const { salt, hash } = hashPassword(password);

      accounts.set(username, {
        name,
        salt,
        hash,
      });

      const user = {
        id: socket.id,
        name,
        status: "online",
      };

      byId.set(socket.id, user);
      byName.set(username, user);

      // Join all channels
      CHANNELS.forEach((channel) => {
        socket.join(`ch:${channel}`);
      });

      socket.data.user = user;

      ack(authPayload(name));

      io.emit("users", publicUsers());

      console.log("User signed up:", name);
    }
  );

  // =========================
  // LOGIN
  // =========================

  socket.on(
    "login",
    ({ name, password } = {}, ack = () => {}) => {
      name =
        typeof name === "string"
          ? name.trim()
          : "";

      const username = name.toLowerCase();

      const account = accounts.get(username);

      if (!account || !validPassword(password)) {
        return ack({
          ok: false,
          error: "Invalid username or password.",
        });
      }

      if (byName.has(username)) {
        return ack({
          ok: false,
          error: "This account is already signed in.",
        });
      }

      try {
        if (!verifyPassword(password, account)) {
          return ack({
            ok: false,
            error: "Invalid username or password.",
          });
        }
      } catch (error) {
        return ack({
          ok: false,
          error: "Invalid username or password.",
        });
      }

      const user = {
        id: socket.id,
        name: account.name,
        status: "online",
      };

      byId.set(socket.id, user);
      byName.set(username, user);

      CHANNELS.forEach((channel) => {
        socket.join(`ch:${channel}`);
      });

      socket.data.user = user;

      ack(authPayload(account.name));

      io.emit("users", publicUsers());

      console.log("User logged in:", account.name);
    }
  );

  // =========================
  // MESSAGE
  // =========================

  socket.on("message", (data = {}) => {
    const user = byId.get(socket.id);

    if (!user) {
      socket.emit(
        "auth-error",
        "Please sign in first."
      );
      return;
    }

    const target = resolve(user, data.to);

    if (!target) {
      console.log("Invalid target:", data.to);
      return;
    }

    const type = [
      "text",
      "audio",
      "poll",
    ].includes(data.type)
      ? data.type
      : "text";

    const msg = {
      id: ++seq,

      from: user.name,

      to: data.to,

      type,

      text:
        typeof data.text === "string"
          ? data.text.slice(0, 2000)
          : "",

      audioData:
        type === "audio"
          ? data.audioData || null
          : null,

      poll:
        type === "poll"
          ? data.poll
          : null,

      bomb: !!data.bomb,

      replyTo:
        data.replyTo || null,

      ts: Date.now(),
    };

    // =========================
    // CHANNEL MESSAGE
    // =========================

    if (target.type === "ch") {
      if (!msg.bomb) {
        history[target.ch].push(msg);

        if (history[target.ch].length > 40) {
          history[target.ch].shift();
        }
      }

      io.to(target.room).emit(
        "message",
        msg
      );

      console.log(
        `[${target.ch}] ${user.name}: ${msg.text}`
      );

      return;
    }

    // =========================
    // PRIVATE MESSAGE
    // =========================

    if (target.type === "dm") {
      const receiverMessage = {
        ...msg,
        to: `dm:${user.name}`,
      };

      const senderMessage = {
        ...msg,
        to: `dm:${target.peer.name}`,
      };

      // Send to receiver
      io.to(target.peer.id).emit(
        "message",
        receiverMessage
      );

      // Send back to sender
      socket.emit(
        "message",
        senderMessage
      );

      console.log(
        `[DM] ${user.name} -> ${target.peer.name}: ${msg.text}`
      );
    }
  });

  // =========================
  // POLL VOTE
  // =========================

  socket.on(
    "vote-poll",
    ({ to, id, optionIdx } = {}) => {
      const user = byId.get(socket.id);

      if (!user) {
        return;
      }

      const target = resolve(user, to);

      if (
        !target ||
        target.type !== "ch"
      ) {
        return;
      }

      const msg = history[target.ch].find(
        (item) => item.id === id
      );

      if (
        !msg ||
        !msg.poll ||
        !msg.poll.options ||
        !msg.poll.options[optionIdx]
      ) {
        return;
      }

      // Remove user's previous vote
      msg.poll.options.forEach(
        (option) => {
          option.votes =
            option.votes.filter(
              (username) =>
                username !== user.name
            );
        }
      );

      // Add new vote
      msg.poll.options[
        optionIdx
      ].votes.push(user.name);

      io.to(target.room).emit(
        "update-poll",
        {
          id,
          poll: msg.poll,
          to,
        }
      );
    }
  );

  // =========================
  // LOGOUT
  // =========================

  socket.on("logout", () => {
    console.log(
      "User logged out:",
      socket.data.user?.name
    );

    removeUser(socket);
  });

  // =========================
  // DISCONNECT
  // =========================

  socket.on("disconnect", () => {
    console.log(
      "Client disconnected:",
      socket.id
    );

    removeUser(socket);
  });

  // =========================
  // REMOVE USER
  // =========================

  function removeUser(socket) {
    const user = byId.get(socket.id);

    if (!user) {
      return;
    }

    byName.delete(
      user.name.toLowerCase()
    );

    byId.delete(socket.id);

    socket.data.user = null;

    io.emit(
      "users",
      publicUsers()
    );
  }
});

// =========================
// HEALTH CHECK
// =========================

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "ConvoX",
    online: byId.size,
  });
});

// =========================
// START SERVER
// =========================

server.listen(port, () => {
  console.log(
    `ConvoX server live at http://localhost:${port}`
  );
});