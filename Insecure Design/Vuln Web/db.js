const mysql = require('mysql2/promise');
const config = require('./config');

async function executeQuery(sql, params) {
	const connect = await mysql.createConnection(config);
	const [result, ] = await connect.execute(sql, params);
	connect.end();
	return result;
}

module.exports = {
	executeQuery
};