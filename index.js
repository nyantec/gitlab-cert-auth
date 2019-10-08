#!/usr/bin/env node
"use strict";

const http = require("http");
const process = require("process");
const jwt = require("jsonwebtoken");

function fail(msg) {
	console.log("error: ", msg);
	process.exit(1);
}

function parseDN(header) {
	// parse X-SSL-Client-DN header
	return header.split(",").reduce((acc, current) => {
		const [key, val] = current.split("=");
		acc[key] = val;
		return acc;
	}, {});
}

const port = process.env.PORT || 8123;
const jwtSecret = process.env.JWT_SECRET || fail("missing JWT_SECRET, exiting");

http.createServer(function (req, res) {
	try {
		const dn = parseDN(req.headers["x-ssl-client-dn"]);
		const token = jwt.sign({ name: dn.CN, email: dn.emailAddress }, jwtSecret);
		res.writeHead(307, { "Location": "/users/auth/jwt/callback?jwt=" + token });
		res.end("success");
	} catch(e) {
		console.log("error: ", e);
		res.writeHead(500);
		res.end("error");
	}
}).listen(port);
