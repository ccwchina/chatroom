// 引入必要的模块
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 让 Express 可以解析 JSON 格式的请求体
app.use(express.json());
// 把 public 文件夹里的文件直接公开出去
app.use(express.static('public'));

// ---------- 配置 ----------
// 从环境变量读取 JWT 密钥（Render 上设置），本地跑时用默认值
const JWT_SECRET = process.env.JWT_SECRET || '一个复杂的本地默认密钥';
// 可用的邀请码列表，你可以随时修改
const VALID_INVITE_CODES = ['dsaiaad', 'chants', 'ccw123c'];
// 用户数据存放位置
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// 工具函数：读取用户数组
function getUsers() {
  const raw = fs.readFileSync(USERS_FILE, 'utf-8');
  return JSON.parse(raw);
}
// 工具函数：保存用户数组
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

// ---------- 注册接口 ----------
app.post('/register', async (req, res) => {
  const { username, password, inviteCode } = req.body;

  if (!username || !password || !inviteCode) {
    return res.status(400).json({ error: '请填写所有字段' });
  }
  if (!VALID_INVITE_CODES.includes(inviteCode)) {
    return res.status(400).json({ error: '邀请码无效' });
  }

  const users = getUsers();
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: '用户名已存在' });
  }

  // 将密码哈希（加密）后存储
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  saveUsers(users);

  res.json({ message: '注册成功，请去登录' });
});

// ---------- 登录接口 ----------
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '请填写用户名和密码' });
  }

  const users = getUsers();
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ error: '用户名或密码错误' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ error: '用户名或密码错误' });
  }

  // 生成一个 24 小时有效的 token
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username: user.username });
});

// ---------- Socket.IO 认证 ----------
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('未提供 token'));
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.username = decoded.username;   // 把用户名绑在这个连接上
    next();
  } catch (err) {
    next(new Error('token 无效或已过期'));
  }
});

// ---------- 聊天事件处理 ----------
io.on('connection', (socket) => {
  console.log(`${socket.username} 进入了聊天室`);

  // 广播“系统消息”给所有人
  io.emit('chat message', {
    username: '系统',
    text: `${socket.username} 加入了聊天室`
  });

  // 监听用户发送的普通消息
  socket.on('chat message', (data) => {
    io.emit('chat message', {
      username: socket.username,
      text: data.text
    });
  });

  socket.on('disconnect', () => {
    io.emit('chat message', {
      username: '系统',
      text: `${socket.username} 离开了聊天室`
    });
    console.log(`${socket.username} 离开了`);
  });
});

// ---------- 启动服务器 ----------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`服务器已在端口 ${PORT} 上运行`);
});
