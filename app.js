const cors = require('cors');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const http = require('http');
const url = require('url');
require('dotenv').config();

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'notes-api',
    port: 8889
});
db.connect(function (error) {
    if(error) {
        console.log('erreur de connexion à la base')
    }
    else {
        console.log('Connexion réussie')
    };
});
const server = http.createServer((req, res) => {
   const parsedUrl = url.parse(req.url, true);
   const path = parsedUrl.pathname;
   const notesPattern = /^\/notes\/(\d+)$/;
   const id = path.match(notesPattern)[1];
   if (req.method === 'POST' && path === '/signup') {
    onSignup(req, res);
  } else if(req.method === 'POST' && path === '/signin') {
    onSignin(req, res);
  } else if(req.method === 'PUT' && path === '/notes') {
    onPutNotes(req, res);
  } else if (req.method === 'GET' && path === '/notes') {
    onGetNotes(req, res);
  } else if (req.method === 'PATCH' && notesPattern.test(path)) {
    onPatchNotes(req, res, id);
  } else if (req.method === 'DELETE' && notesPattern.test(path)) {
    onDeleteNotes(req, res, id);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
})

function onSignin(req, res) {
    let body = '';
    req.on('data', (chunk) => {
        body += chunk.toString();
    });

    req.on('end', () => {
        
        try {
            const { username, password } = JSON.parse(body);
            const query = `SELECT * FROM users WHERE username = '${username}'`;
              if (password.length < 4) {
                return sendError(res, 400, 'Le mot de passe doit contenir au moins 4 caractères');
              };
              
              if (!/^[a-z]+$/.test(username)) {
                return sendError(res, 400, 'Votre identifiant ne doit contenir que des lettres minuscules non accentuées');
              };
        
              if (username.length < 2 || username.length > 20) {
                return sendError(res, 400, 'Votre identifiant doit contenir entre 2 et 20 caractères');
              };

              db.query(query, (err, result) => {
                  if(result.length === 0) {
                    return sendError(res, 403, 'Cet identifiant est inconnu');
                  } else {
                    bcrypt.compare(password, result[0].password, (err, resu) => {
                        if(resu) {
                            const token = jwt.sign({
                                username: username,
                                password: password
                            }, `${process.env.JWT_SECRET}`,{expiresIn: '24h'});
                            res.writeHead(400, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ access_token: token }));
                        } else {
                            return sendError(res, 401, 'Error');
                        }
                    })
                  }
              })

        } catch (error) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Erreur lors du traitement de la requête' }));
        }
    })
}

function onSignup(req, res) {
    let body = '';
  req.on('data', (chunk) => {
    body += chunk.toString();
  });

  req.on('end', () => {
    try {
      const { username, password } = JSON.parse(body);
      const query = `SELECT * FROM users WHERE username = '${username}'`;
      if (password.length < 4) {
        return sendError(res, 400, 'Le mot de passe doit contenir au moins 4 caractères');
      }
      
      if (!/^[a-z]+$/.test(username)) {
        return sendError(res, 400, 'Votre identifiant ne doit contenir que des lettres minuscules non accentuées');
      }

      if (username.length < 2 || username.length > 20) {
        return sendError(res, 400, 'Votre identifiant doit contenir entre 2 et 20 caractères');
      }
      db.query(query, (err, result) => {
          if(result.length > 0) {
            return sendError(res, 400, 'Cet identifiant est déjà associé à un compte');
          } else {
              
              bcrypt.hash(password, 10, (err,hash) => {
                if(err) {
                   return sendError(res, 500, 'error du password')
                } else {
                    const query = `INSERT INTO users (username, password) VALUES (?,?)`;
                    const values = [username, hash];
                    db.query(query, values, (err, result) => {
                        if(err) {
                            return sendError(res, 500, 'error');
                        } else {
                        // génération du jeton JWT
                            const token = jwt.sign({
                                username: username,
                                password: password
                            }, `${process.env.JWT_SECRET}`,{expiresIn: '24h'});
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ access_token: token }));                   
                        }
                    })
                }
            });
          }
      })

      
      
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Erreur lors du traitement de la requête' }));
    }
  });
}

function onPutNotes(req, res) {
    const token = req.headers['x-access-token'];
    if (token) {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk.toString();
        });
    
        req.on('end', () => {
          try {
            const { userId, content } = JSON.parse(body);
            const query = `INSERT INTO notes (userId, content, createdAt, lastUpdatedAt) VALUES(?,?,?,?)`;
            const values = [userId, content, new Date, null];
            db.query(query, values, (err, result) => {
                if(result) {
                    const query = `SELECT * FROM notes WHERE userId = '${userId}'`;
                    db.query(query, (err, resu) => {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ note: resu[0]}));
                    })
                }
            })
          } catch (error) {
            sendError(res, 401, 'Token invalide ou expiré');
          }
        });
    } else {
        sendError(res, 401, 'Utilisateur non connecté');
    }
}
  
function onGetNotes(req, res) {
    //console.log(req.rawHeaders[1]);
    const token = req.rawHeaders[1];
    //console.log(decoded);
    if (token) {
      try {        
        const decoded = jwt.decode(token, process.env.JWT_SECRET);
        const query = `SELECT _id FROM users WHERE username = '${decoded.username}'`;
        db.query(query, (err, result) => {
            if(result) {
                const userId = result[0]['_id'];
                const query = `SELECT * FROM notes WHERE userId = ${userId}`;
                db.query(query, (err, resu) => {
                    if(resu) {
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ notes: resu }));
                    }
                })
            }
        })
      } catch (error) {
        sendError(res, 401, 'Token invalide ou expiré');
      }
    } else {
      sendError(res, 401, 'Utilisateur non connecté');
    }
}
  
function onPatchNotes(req, res, id) {
    const token = req.headers['x-access-token'];
    const decoded = jwt.decode(token, process.env.JWT_SECRET);
    const uid = eval(id);
    var user = '';
    
    //console.log(uid);
    if (token) {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
      });
      const query = `SELECT _id FROM users WHERE username = '${decoded.username}'`;
      db.query(query, (err, resu) => {
          if(resu) {
              user = resu[0]['_id'];
          }
      })
      req.on('end', () => {
        try {
            const { content } = JSON.parse(body);
            const query = `SELECT userId FROM notes WHERE _id = ${uid}`;
            db.query(query, (err, result) => {
                if(!err) {
                    if(result.length === 0) {
                        return sendError(res, 404, 'Cet identifiant est inconnu');
                    } else if(user !== result[0].userId) {
                        return sendError(res, 403, 'Accés non autorisé dans cette note');
                    } else {
                        const query = `UPDATE notes SET content = ?, lastUpdatedAt = ? WHERE _id = ?`;
                        const values = [content, new Date, uid];
                        db.query(query, values, (err, result) => {
                            if(result) {
                                const query = `SELECT * FROM notes WHERE _id = ${uid}`;
                                db.query(query, (err, resu) => {
                                    if(resu) {
                                        res.writeHead(200, { 'Content-Type': 'application/json' });
                                        res.end(JSON.stringify({ note: resu[0] }));
                                    }
                                })
                            } else {
                                return sendError(res, 401, err);
                            }
                        })
                    }
                }
            })
        } catch (error) {
          sendError(res, 401, 'Token invalide ou expiré');
        }
      });
    } else {
      sendError(res, 401, 'Utilisateur non connecté');
    }
}
  
function onDeleteNotes(req, res, id) {
    const token = req.headers['x-access-token'];
    const decoded = jwt.decode(token, process.env.JWT_SECRET);
    const uid = eval(id);
    var user = '';
    
    //console.log(uid);
    if (token) {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
      });
      const query = `SELECT _id FROM users WHERE username = '${decoded.username}'`;
      db.query(query, (err, resu) => {
          if(resu) {
              user = resu[0]['_id'];
          }
      })
      req.on('end', () => {
        try {
            const query = `SELECT userId FROM notes WHERE _id = ${uid}`;
            db.query(query, (err, result) => {
                if(!err) {
                    if(result.length === 0) {
                        return sendError(res, 404, 'Cet identifiant est inconnu');
                    } else if(user !== result[0].userId) {
                        return sendError(res, 403, 'Accés non autorisé dans cette note');
                    } else {
                        const query = `DELETE FROM notes WHERE _id = ${uid}`;
                        db.query(query, (err, resu) => {
                            res.writeHead(statusCode, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ message: 'supprimé' }));
                        })
                        
                    }
                }
            })
        } catch (error) {
          sendError(res, 401, 'Token invalide ou expiré');
        }
      });
    } else {
      sendError(res, 401, 'Utilisateur non connecté');
    }
}
  
function sendError(res, statusCode, errorMessage) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: errorMessage }));
}

const PORT = 8891
server.listen(process.env.PORT || PORT , () => {
    console.log(`server is running on port `+ process.env.PORT);
})