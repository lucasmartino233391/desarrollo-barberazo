const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool } = require('../config/db');

const SALT_ROUNDS = 10;

async function findUserByEmail(email) {
  const [rows] = await pool.execute(
    'SELECT id_usuario, email, password, rol FROM usuarios WHERE email = ?',
    [email]
  );
  return rows[0] || null;
}

async function findUserById(id) {
  const [rows] = await pool.execute(
    `SELECT u.id_usuario, u.email, u.rol, u.fecha_registro,
            c.id_cliente, c.nombre, c.apellido, c.telefono, c.estado
     FROM usuarios u
     LEFT JOIN clientes c ON c.id_usuario = u.id_usuario
     WHERE u.id_usuario = ?`,
    [id]
  );
  return rows[0] || null;
}

function sanitizeUser(user) {
  if (!user) return null;

  const { password: _, ...userWithoutPassword } = user;
  return {
    ...userWithoutPassword,
    id: userWithoutPassword.id_usuario,
  };
}

async function register({ nombre, apellido, email, password, telefono }) {
  const existingUser = await findUserByEmail(email);
  if (existingUser) {
    const error = new Error('El email ya está registrado');
    error.statusCode = 409;
    throw error;
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

const query = 'INSERT INTO usuarios (nombre, apellido, email, password, rol) VALUES (?, ?, ?, ?, ?)';

const [userResult] = await connection.execute(query, [
  nombre,
  apellido,
  email,
  hashedPassword,
  'CLIENTE'
]);

    const idUsuario = userResult.insertId;

    await connection.execute(
      'INSERT INTO clientes (id_usuario, nombre, apellido, telefono) VALUES (?, ?, ?, ?)',
      [idUsuario, nombre, apellido, telefono || null]
    );

    await connection.commit();

    const user = await findUserById(idUsuario);
    

    return { user: sanitizeUser(user)};
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

async function login({ email, password }) {
  const user = await findUserByEmail(email);
  if (!user) {
    const error = new Error('Credenciales inválidas');
    error.statusCode = 401;
    throw error;
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    const error = new Error('Credenciales inválidas');
    error.statusCode = 401;
    throw error;
  }

  const profile = await findUserById(user.id_usuario);
  const token = generateToken(profile);

  return { user: sanitizeUser(profile), token };
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id_usuario, email: user.email, rol: user.rol },
    process.env.JWT_SECRET || 'caup2019',
    { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
  );
}

function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET || 'caup2019');
}

module.exports = {
  register,
  login,
  findUserById,
  verifyToken,
  sanitizeUser,
};
