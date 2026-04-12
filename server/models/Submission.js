const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const Submission = sequelize.define('Submission', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  filename: {
    type: DataTypes.STRING,
  },
  content: {
    type: DataTypes.TEXT('long'),
  },
  type: {
    type: DataTypes.ENUM('file', 'text'),
  },
  iocs: {
    type: DataTypes.JSON,
  },
  result: {
    type: DataTypes.JSON,
  },
}, {
  timestamps: true,
});

module.exports = Submission;
