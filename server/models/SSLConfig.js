const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const SSLConfig = sequelize.define('SSLConfig', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  isEnabled: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    allowNull: false,
  },
  certificatePath: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  privateKeyPath: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  caPath: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  // Store certificate info for display
  certificateInfo: {
    type: DataTypes.JSON,
    allowNull: true,
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: true,
  },
}, {
  tableName: 'ssl_config',
});

module.exports = SSLConfig;
