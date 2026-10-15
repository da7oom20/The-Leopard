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
  // Groups all per-(client, filterType) rows of a single hunt dispatch.
  // Set once per /hunt or /upload invocation (see search.js dispatcher)
  // and used by /repo to render hunts as cards and by /hunt/rerun to
  // re-run a single filter in place.
  huntId: {
    type: DataTypes.STRING(64),
    allowNull: true
  },
  // Time window the hunt was dispatched with, in minutes. Persisted so
  // /hunt/rerun can re-execute the search with the same horizon.
  minutesBack: {
    type: DataTypes.INTEGER,
    allowNull: true
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
    // Used by /repo grouped view (list hunts newest-first)
    { fields: ['huntId'] },
  ]
});

module.exports = Result;
