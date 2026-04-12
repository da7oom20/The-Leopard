const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const AuditLog = sequelize.define('AuditLog', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  action: {
    type: DataTypes.STRING,
    allowNull: false
  },
  category: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isIn: [['user', 'siem', 'ti', 'security', 'settings', 'auth']]
    }
  },
  actorId: {
    type: DataTypes.INTEGER,
    allowNull: true
  },
  actorUsername: {
    type: DataTypes.STRING,
    allowNull: true
  },
  targetType: {
    type: DataTypes.STRING,
    allowNull: true
  },
  targetId: {
    type: DataTypes.INTEGER,
    allowNull: true
  },
  details: {
    type: DataTypes.JSON,
    allowNull: true
  },
  ip: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  tableName: 'audit_logs',
  timestamps: true,
  updatedAt: false,
  indexes: [
    { fields: ['category'] },
    { fields: ['actorId'] },
    { fields: ['createdAt'] }
  ]
});

module.exports = AuditLog;
