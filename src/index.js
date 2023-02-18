require("dotenv").config();

const User = require("./models/User");
const express = require("express");
const mongoose = require("mongoose");
const app = express();
const jwt = require("jsonwebtoken");
const PORT = process.env.PORT || 4100;
const bcrypt = require("bcrypt");

const uri = `mongodb+srv://marvelmoviescountdown:${process.env.MONGODB_PASSWORD}@cluster0.ja6iqpg.mongodb.net/?retryWrites=true&w=majority`;
const dbName = process.env.MONGODB_DATABASE;

async function connect() {
  try {
    await mongoose.connect(uri, {
      dbName: "marvelmoviescountdown-db",
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`Connected to MongoDB, database ${dbName}`);
  } catch (error) {
    console.log(error);
  }
}

connect();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let refreshTokens = [];

const generateAccessToken = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
};

const generateRefreshToken = (user) => {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "1d" });
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token === null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.post("/auth/register", (req, res) => {
  const user = new User(req.body);

  user
    .save()
    .then((result) => {
      res.send({
        message: "Success insert data",
        data: { username: result.username },
      });
    })
    .catch((err) => {
      console.log(err);
    });
});

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body;
  // Find the username
  User.findOne({ username })
    .then((result) => {
      if (!result) {
        return res.status(404).json({ message: "No username found" });
      }

      bcrypt
        .compare(password, result.password)
        .then((result) => {
          if (!result) {
            return res.status(403).json({ message: "Password not match" });
          }

          const user = { name: username };
          const accessToken = generateAccessToken(user);
          const refreshToken = generateRefreshToken(user);
          refreshTokens.push(refreshToken);
          res.json({ accessToken: accessToken, refreshToken: refreshToken });
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => {
      console.log(err);
    });
});

app.delete("/auth/logout", (req, res) => {
  refreshTokens = refreshTokens.filter(
    (token) => token !== req.body.refreshToken
  );
  res.sendStatus(204);
});

app.post("/auth/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
