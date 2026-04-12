require('dotenv').config(); // load env variables

const { Sequelize } = require('sequelize');

const poolConfig = {
  max: parseInt(process.env.DB_POOL_MAX || '50', 10),
  min: parseInt(process.env.DB_POOL_MIN || '5', 10),
  acquire: parseInt(process.env.DB_POOL_ACQUIRE || '60000', 10),
  idle: parseInt(process.env.DB_POOL_IDLE || '10000', 10),
  evict: 30000,
};

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '3306', 10),
    dialect: 'mysql',
    logging: false,
    pool: poolConfig,
    retry: {
      max: 5
    },
    dialectOptions: {
      connectTimeout: 20000,
      ...(process.env.DB_STATEMENT_TIMEOUT && {
        options: { requestTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT) }
      })
    }
  }
);

// Connection test with retry logic for startup
async function testConnection(retries = 5, delay = 3000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await sequelize.authenticate();
      console.log('Sequelize connected to MySQL successfully.');
      console.log(`DB pool: max=${poolConfig.max}, min=${poolConfig.min}, acquire=${poolConfig.acquire}ms, idle=${poolConfig.idle}ms`);
      return;
    } catch (error) {
      console.error(`Sequelize connection attempt ${attempt}/${retries} failed:`, error.message);
      if (attempt < retries) {
        console.log(`Retrying in ${delay / 1000}s...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        console.error('All database connection attempts failed. The server will start but DB operations will fail.');
      }
    }
  }
}

// Periodic pool health logging (every 5 minutes)
const POOL_LOG_INTERVAL = 5 * 60 * 1000;
setInterval(() => {
  const pool = sequelize.connectionManager.pool;
  if (!pool) return;
  console.log(`[DB Pool] size=${pool.size} available=${pool.available} using=${pool.using} waiting=${pool.waiting} | max=${poolConfig.max}`);
}, POOL_LOG_INTERVAL);

testConnection();

module.exports = sequelize;
