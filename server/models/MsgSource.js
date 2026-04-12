const { DataTypes } = require('sequelize');
const sequelize = require('../db');

const MsgSource = sequelize.define('MsgSource', {
  client: DataTypes.STRING,
  filterType: DataTypes.STRING,
  listId: DataTypes.INTEGER,
  guid: DataTypes.STRING,
  name: DataTypes.STRING,
  listType: DataTypes.STRING
},{
  tableName: 'msgsources'
});

module.exports = MsgSource;
