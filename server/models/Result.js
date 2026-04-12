const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const Result = sequelize.define('Result', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  client: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  siemType: {
    type: DataTypes.STRING,
    allowNull: true,
    defaultValue: 'logrhythm' // Backward compatible default
  },
  filterType: {
    type: DataTypes.STRING,
    allowNull: true
  },
  hit: {
    type: DataTypes.STRING, // 'hit' or 'no hit'
    allowNull: false,
  },
  fileName: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  logs: {
    type: DataTypes.TEXT('long'),
    allowNull: true,
  },
  details: {
    type: DataTypes.TEXT('long'),
    allowNull: true
  },
  searchDuration: {
    type: DataTypes.INTEGER, // milliseconds
    allowNull: true
  },
  resultCount: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  }
}, {
  timestamps: true,
  indexes: [
    // Used by repo endpoint (ORDER BY createdAt DESC with pagination)
    { fields: ['createdAt'] },
    // Used by search results lookup after upload/hunt
    { fields: ['fileName'] },
    // Used by export filtering
    { fields: ['client', 'filterType'] },
    // Used by hit-based filtering
    { fields: ['hit'] },
    // Used by SIEM type filtering
    { fields: ['siemType'] },

  ]
});

module.exports = Result;
