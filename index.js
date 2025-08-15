require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const nodemailer = require('nodemailer')
const crypto = require('crypto')
const bcrypt = require('bcrypt')
var mysql = require('mysql')
const mysql2 = require('mysql2')
const requestIp = require('request-ip')

const fs = require('fs')
const path = require('path')
const http = require('http')
const multer = require('multer')
const xlsx = require('xlsx')

const socketio = require('socket.io')
const cron = require('node-cron')
const puppeteer = require('puppeteer')
const date = new Date()
let currentYear = date.getFullYear()
const url = require('url')

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Note that req.body might not have been fully populated yet. It depends on the order that the client transmits fields and files to the server.
    cb(null, path.join('uploads'))
  },
  filename: function (req, file, cb) {
    cb(null, `${new Date().getTime() / 1000}-${file.originalname}`)
  },
})

const upload = multer({ storage })

const { Server } = require('socket.io')
const router = express.Router()
const sitename = 'Protect Artists'
const siteurl = 'protect-artists.developmint.xyz'

const app = express()
app.use(requestIp.mw())

app.use('/uploads', express.static(path.join(__dirname, 'uploads')))
const port = 5000

const server = http.createServer(app)

var con = mysql2.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,

  //    host: "64.31.22.34",
  //    user: "develop_developer",
  //    password: "k1D1M+]5+{&_",
  //    database: "develop_protectartists"
})

const transporter = nodemailer.createTransport({
  host: 'mail.developmint.xyz',
  port: 25,
  secure: false,
  secureConnection: false,
  // tls: {
  //     ciphers:'SSLv3'
  // },
  auth: {
    user: 'smtpnodemail@developmint.xyz',
    pass: '$svVEA&@GlEI',
  },
  tls: {
    rejectUnauthorized: false,
  },

  //    host: "portal.protectartistsagency.com",
  //    port: 587,
  //    secure: true,
  //    secureConnection: true,
  // tls: {
  //     ciphers:'SSLv3'
  // },
  //    auth: {
  //        user: "noreply@portal.protectartistsagency.com",
  //        pass: "Yz7+PMs#dcwi",
  //    },
  //    tls: {
  //        rejectUnauthorized: false,
  //    },
})

function sendEmail(to, subject, name, message) {
  const mailOptions = {
    from: `donot-reply@${siteurl}`,
    to: to,
    subject: subject,
    html:
      'Hi' +
      (name !== '' ? ' <b>' + name + '</b>' : '') +
      ',<br><br>' +
      message +
      '<br><br>Best Regards,<br><b>' +
      sitename +
      ' Team</b>',
  }

  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Failed to send email:', error)
        reject(error)
      } else {
        console.log('Email sent:', info.response)
        resolve()
      }
    })
  })
}

// con.connect(function (err) {
//     if (err) throw err;
//     console.log("Database Connected");
// });

const corsOptions = {
  //    origin: 'lfp.protect-artists.org',
  optionsSuccessStatus: 200,
}

app.use(cors(corsOptions))

app.use(bodyParser.json())
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
)

//app.use(bodyParser.json({
//    limit: '128mb'
//}));
//app.use(bodyParser.urlencoded({
//    limit: '128mb',
//    extended: true
//}));

const util = require('util')
// const query = util.promisify(con.query).bind(con);
app.use('/products', express.static('products'))

const hashPassword = async (password) => {
  try {
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    return hashedPassword
  } catch (error) {
    throw error
  }
}

function queryAsync(sql, params) {
  return new Promise((resolve, reject) => {
    con.query(sql, params, (error, results, fields) => {
      if (error) {
        reject(error)
      } else {
        resolve(results)
      }
    })
  })
}

function checkAuth(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized - No bearer token provided' })
  }

  con.query('select * from users where token = ?', [authHeader.split(' ')[1]], (error, results) => {
    if (error) {
      return res.status(401).json({ message: 'Unauthorized - Invalid token' })
    } else if (results.length === 0) {
      return res.status(401).json({ message: 'Unauthorized - Invalid token' })
    } else {
      next()
    }
  })
}

app.get('/', (req, res) => {
  res.send('Protect Artists Server')
})

app.get('/api', (req, res) => {
  res.send('Protect Artists Server')
})

router.post('/user/login', async (req, res) => {
  con.query(
    'select id, userid, name, email, type, status, image, password from users where email = ?',
    [req.body.email],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred:' + error)
        console.error('An error occurred:' + error)
      } else {
        if (results.length > 0) {
          bcrypt.compare(req.body.password, results[0].password, (error, result) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else if (result) {
              const token = crypto.randomBytes(64).toString('hex')
              const currentTimestamp = new Date().toISOString().split('T')[0]
              const updateLastLogin = 'UPDATE users SET lastlogin = ?, token = ? WHERE email = ?'
              con.query(updateLastLogin, [currentTimestamp, token, req.body.email], (updateError) => {
                if (updateError) {
                  console.error('Error updating last login:', updateError)
                }
              })

              results[0]['token'] = token
              delete results[0].password

              if (results[0].status === 'Active') {
                res.json({
                  message: 'success',
                  userToken: results,
                })
              } else if (results[0].status === 'Inactive') {
                res.json({
                  message: "Account suspended. Veuillez contacter l'administrateur.",
                })
                console.error('Account suspended')
              } else if (results[0].status === 'Email') {
                res.json({
                  message: 'Account not verified. Veuillez vérifier votre courrier électronique pour vérification.',
                })
                console.error('Account not verified')
              }
            } else {
              res.json({
                message: 'No account found',
              })
            }
          })
        } else {
          res.json({
            message: 'No account found',
          })
        }
      }
    }
  )
})

router.post('/user/forgotpassword', (req, res) => {
  const { email } = req.body

  // Check if email exists in the database
  const query = 'SELECT * FROM users WHERE email = ?'
  const values = [email]

  con.query(query, values, (err, results) => {
    if (err) {
      console.error('Failed to retrieve user:', err)
      res.status(500).json({
        message: 'Internal server error: Failed to retrieve user',
      })
    } else if (results.length === 0) {
      res.json({
        message: 'User not found',
      })
    } else {
      const user = results[0]
      const resetToken = crypto.randomBytes(20).toString('hex')
      const resetExpires = Date.now() + 300000 // Token expires in 5 minutes
      // const resetExpires = Date.now() + 60000; // Token expires in 10 seconds

      // Save reset token and expiry in the database
      const insertQuery = 'INSERT INTO reset_tokens(email,userid,token,expiry) values(?,?,?,?)'
      const insertValues = [email, user.userid, resetToken, resetExpires]

      con.query(insertQuery, insertValues, (err, result) => {
        if (err) {
          console.error("Échec de l'enregistrement du jeton de réinitialisation: ", err)
          res.status(500).json({
            message: "Erreur de serveur interne: échec de l'enregistrement du jeton de réinitialisation",
          })
        } else {
          con.query(
            'update reset_tokens set expired = 1 where email = ? and expired = 0 and token <> ?',
            [email, resetToken],
            (error, results) => {
              if (error) {
                res.status(500).json('An error occurred: ' + error)
                console.error('An error occurred: ' + error)
              } else {
                // Send reset password email with the reset link
                const resetLink = `https://${siteurl}/reset-password/${resetToken}`
                const emailName = user.name
                const emailSubject = 'Reset Password'
                const emailMessage = `We have received a request to reset your password for your <b>${sitename}</b> account. To proceed with the password reset, please click on the link below:
                            <br><br>
                            ${resetLink}
                            <br><br>
                            If you did not initiate this request or no longer wish to reset your password, please ignore this email. Your current password will remain unchanged.
                            <br><br>
                            If you need any further assistance, please reach out to our support team at <b>help@protectartists.com</b>.
                            `

                sendEmail(email, emailSubject, emailName, emailMessage)
                  .then(() => {
                    res.json({
                      message: 'success',
                    })
                    console.log('Reset password email sent successfully')
                  })
                  .catch((error) => {
                    console.error('Failed to send reset password email:', error)
                    res.status(500).json({
                      message:
                        "Erreur de serveur interne: échec de l'envoi de l'e-mail de réinitialisation du mot de passe",
                    })
                  })
                // res.json({message: 'success', order: results});
              }
            }
          )
        }
      })
    }
  })
})

router.post('/user/verifysession', checkAuth, async (req, res) => {
  con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        if (results[0].status === 'Active') {
          res.json({
            message: 'success',
            userToken: results,
          })
        } else if (results[0].status === 'Inactive') {
          res.json({
            message: "Account suspended. Veuillez contacter l'administrateur.",
          })
          console.error('Account suspended')
        } else if (results[0].status === 'Email') {
          res.json({
            message: 'Account not verified. Veuillez vérifier votre courrier électronique pour vérification.',
          })
          console.error('Account not verified')
        }
      } else {
        res.json({
          message: 'No account found',
        })
      }
    }
  })
})

router.post('/user/update', checkAuth, (req, res) => {
  con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        if (results[0].type === 'Admin') {
          var tempq = 'update users set name=?, email=? where userid = ?'
          var tempr = [req.body.name, req.body.email, req.body.userid]
        } else {
          var tempq = 'update users set name=? where userid = ?'
          var tempr = [req.body.name, req.body.userid]
        }
        con.query(tempq, tempr, (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
              if (error) {
                res.status(500).json('An error occurred: ' + error)
                console.error('An error occurred: ' + error)
              } else {
                res.json({
                  message: 'success',
                  userToken: results,
                })
              }
            })
          }
        })
      } else {
        res.json({
          message: 'No account found',
        })
      }
    }
  })
})

router.post('/user/updatepassword', checkAuth, async (req, res) => {
  const hashedPassword = await hashPassword(req.body.newpassword)
  if (req.body.newpassword === req.body.confirmpassword) {
    con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
      if (error) {
        res.status(500).json('An error occurred:' + error)
        console.error('An error occurred:' + error)
      } else {
        if (results.length > 0) {
          bcrypt.compare(req.body.oldpassword, results[0].password, (error, result) => {
            if (error) {
              res.status(500).json('Error verifying password: ' + error)
              console.error('Error verifying password: ' + error)
            } else if (result) {
              con.query(
                'update users set password = ? where userid = ?',
                [hashedPassword, req.body.userid],
                (error, results) => {
                  if (error) {
                    res.status(500).json('An error occurred: ' + error)
                    console.error('An error occurred: ' + error)
                  } else {
                    res.json({
                      message: 'success',
                    })
                  }
                }
              )
            } else {
              res.json({
                message: 'Old password incorrect',
              })
            }
          })
        } else {
          res.json({
            message: 'No account found',
          })
        }
      }
    })
  } else {
    res.json({
      message: 'Passwords do not match',
    })
  }
})

// Function to validate the reset token
function validateResetToken(token, callback) {
  // Check if the token exists and has not expired
  const query = 'SELECT email, expiry FROM reset_tokens WHERE token = ? and expired = 0 order by id desc'
  const values = [token]

  con.query(query, values, (err, results) => {
    if (err) {
      callback(err, false, null)
    } else if (results.length === 0) {
      callback(null, false, null)
    } else {
      const { email, expiry } = results[0]
      const currentTime = Date.now()

      // Check if the token has expired
      if (currentTime > expiry) {
        callback(null, false, null)
      } else {
        callback(null, true, email)
      }
    }
  })
}

// API Endpoint: Validate reset token
router.get('/user/validatetoken/:token', (req, res) => {
  const { token } = req.params

  validateResetToken(token, (err, valid, email) => {
    if (err) {
      console.error('Failed to validate reset token:', err)
      res.status(500).json({
        message: 'Internal server error',
      })
    } else if (!valid) {
      res.json({
        message: 'invalid',
      })
    } else {
      res.json({
        message: 'success',
      })
    }
  })
})

// Function to validate the reset token
async function resetPassword(email, newpassword, confirmpassword, callback) {
  try {
    const hashedPassword = await hashPassword(newpassword)
    if (newpassword === confirmpassword) {
      con.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error) {
          console.error('An error occurred:', error)
          callback(error)
        } else {
          if (results.length > 0) {
            con.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (error, results) => {
              if (error) {
                console.error('An error occurred:', error)
                callback(error)
              } else {
                callback(null)
              }
            })
          } else {
            callback(new Error('No account found'))
          }
        }
      })
    } else {
      callback(new Error('Passwords do not match'))
    }
  } catch (error) {
    callback(error)
  }
}

// API Endpoint: Reset password
router.post('/user/resetpassword/:token', (req, res) => {
  const { token } = req.params
  const { newpassword, confirmpassword } = req.body

  validateResetToken(token, (err, valid, email) => {
    if (err) {
      console.error('Failed to validate reset token:', err)
      res.status(500).json({
        message: 'Internal server error',
      })
    } else if (!valid) {
      res.json({
        message: 'Token Expired',
      })
    } else {
      // Reset the user's password
      resetPassword(email, newpassword, confirmpassword, (err) => {
        if (err) {
          console.error('Failed to reset password:', err)
          res.status(500).json({
            message: 'Internal server error',
          })
        } else {
          res.json({
            message: 'success',
          })

          con.query(
            'update reset_tokens set expired = 1 where email = ? and expired = 0',
            [email],
            (error, results) => {
              if (error) {
              } else {
                // res.json({message: 'success', order: results});
              }
            }
          )

          // Send reset password email with the reset link
          const emailName = ''
          const emailSubject = 'Password Changed Successfully'
          const emailMessage = `This is a notification to inform you that your password for <b>${sitename}</b> has been successfully changed. If you did not make this change, please contact our support team immediately at <b>help@protectartists.com</b>.
              <br><br>
              For security reasons, we recommend that you keep your password confidential and avoid sharing it with anyone. If you suspect any unauthorized activity, please notify us promptly.
              <br><br>
              If you have any questions or need further assistance, feel free to reach out to our support team at <b>help@protectartists.com</b>.
              `

          sendEmail(email, emailSubject, emailName, emailMessage)
            .then(() => {
              // res.json({ message: 'success' });
              console.log('Password change email sent successfully')
            })
            .catch((error) => {
              console.error('Failed to send reset password email:', error)
              res.status(500).json({
                message: 'Internal server error',
              })
            })
        }
      })
    }
  })
})

/* Member */
router.post('/members/all', checkAuth, (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and status = "' + req.body.statusfilter + '" ' : ''
  con.query(
    "select * from users where type = 'Member' " + searchtxt + " and status <> 'Email' order by name asc",
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/members/get', checkAuth, (req, res) => {
  con.query(
    "select * from users where type = 'Member' and status <> 'Email' and userid = ?",
    [req.body.userid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('Error executing MySQL querxy: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/members/review', checkAuth, (req, res) => {
  con.query(
    "select * from users where type = 'Business' and userid = ? and status = 'Under Review'",
    [req.body.userid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        if (results.length > 0) {
          const username = results[0].name
          const usersemail = results[0].email

          con.query(
            'update users set status = ? where userid = ?',
            [req.body.reviewaction === 'Approved' ? 'Active' : req.body.reviewaction, req.body.userid],
            (error, results) => {
              if (error) {
                res.status(500).json('An error occurred: ' + error)
                console.error('An error occurred: ' + error)
              } else {
                res.json({
                  message: 'success',
                })
                // Send reset password email with the reset link
                /*
                                      const emailName = username;
                                      const emailSubject = `Account Verified Successfully`;
                                      const emailMessage = `We are delighted to inform you that your account with <b>${sitename}</b> has been successfully verified. Congratulations!
                                      <br><br>
                                      You can now enjoy full access to our services and explore all the features and benefits we offer.
                                      <br><br>
                                      Should you have any questions or need assistance, please don't hesitate to reach out to our support team at <b>help@protectartists.com</b>.
                                      <br><br>
                                      Thank you for choosing <b>${sitename}</b>. We look forward to serving you!.
                                      `;

                                      sendEmail(usersemail, emailSubject, emailName, emailMessage)
                                      */
              }
            }
          )
        } else {
          res.json({
            message: 'Invalid request',
          })
        }
      }
    }
  )
})

router.post('/members/add', checkAuth, async (req, res) => {
  if (req.body.password.length >= 6) {
    try {
      const userid = crypto.randomBytes(16).toString('hex')
      const hashedPassword = await hashPassword(req.body.password)
      const token = crypto.randomBytes(64).toString('hex')

      con.query(
        'insert into users (userid, name, email, password, token, status) values (?,?,?,?,?,?)',
        [userid, req.body.name, req.body.email, hashedPassword, token, 'Active'],
        async (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('Error executing register query: ' + error)
          } else {
            res.json({
              message: 'success',
            })

            // Send reset password email with the reset link
            const emailName = req.body.name
            const emailSubject = `Welcome to ${sitename}!`
            const emailMessage = `Your account has been created! We are excited to have you as part of our community.<br><br>If you have any questions or need assistance, please don't hesitate to contact our support team at <b>help@protectartists.com</b>.`
            sendEmail(req.body.email, emailSubject, emailName, emailMessage)
              .then(() => {})
              .catch((error) => {
                console.error('Failed to new account email:', error)
                res.status(500).json({
                  message: 'Internal server error',
                })
              })
          }
        }
      )
    } catch (error) {
      res.status(500).json('An error occurred: ' + error)
      console.error('Error executing register query: ' + error)
    }
  } else {
    res.status(500).json({
      error: 'Password must have at least 6 characters',
    })
  }
})

router.post('/members/update', (req, res) => {
  con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          'update users set name=?, email=?, status=? where userid = ?',
          [req.body.name, req.body.email, req.body.status, req.body.userid],
          (error, results) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
                if (error) {
                  res.status(500).json('An error occurred: ' + error)
                  console.error('An error occurred: ' + error)
                } else {
                  res.json({
                    message: 'success',
                    userToken: results,
                  })
                }
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No account found',
        })
      }
    }
  })
})

router.post('/members/delete', (req, res) => {
  con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from users where userid = ?', [req.body.userid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No account found',
        })
      }
    }
  })
})

/* Admin */
router.post('/admins/all', checkAuth, (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and status = "' + req.body.statusfilter + '" ' : ''
  con.query(
    "select * from users where type = 'Admin' " + searchtxt + " and status <> 'Email' order by name asc",
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/admins/get', checkAuth, (req, res) => {
  con.query(
    "select * from users where type = 'Admin' and status <> 'Email' and userid = ?",
    [req.body.userid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('Error executing MySQL querxy: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/admins/add', checkAuth, async (req, res) => {
  if (req.body.password.length >= 6) {
    try {
      const userid = crypto.randomBytes(16).toString('hex')
      const hashedPassword = await hashPassword(req.body.password)
      const token = crypto.randomBytes(64).toString('hex')

      con.query(
        'insert into users (userid, name, email, password, token, type, status) values (?,?,?,?,?,?,?)',
        [userid, req.body.name, req.body.email, hashedPassword, token, 'Admin', 'Active'],
        async (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('Error executing register query: ' + error)
          } else {
            res.json({
              message: 'success',
            })

            // Send reset password email with the reset link
            const emailName = req.body.name
            const emailSubject = `Welcome to ${sitename}!`
            const emailMessage = `Your account has been created! We are excited to have you as part of our community.<br><br>If you have any questions or need assistance, please don't hesitate to contact our support team at <b>help@protectartists.com</b>.`
            sendEmail(req.body.email, emailSubject, emailName, emailMessage)
              .then(() => {})
              .catch((error) => {
                console.error('Failed to new account email:', error)
                res.status(500).json({
                  message: 'Internal server error',
                })
              })
          }
        }
      )
    } catch (error) {
      res.status(500).json('An error occurred: ' + error)
      console.error('Error executing register query: ' + error)
    }
  } else {
    res.status(500).json({
      error: 'Password must have at least 6 characters',
    })
  }
})

router.post('/admins/update', checkAuth, (req, res) => {
  con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          "update users set name=?, email=?, status=? where userid = ? and type = 'Admin'",
          [req.body.name, req.body.email, req.body.status, req.body.userid],
          (error, results) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              con.query('select * from users where userid = ?', [req.body.userid], (error, results) => {
                if (error) {
                  res.status(500).json('An error occurred: ' + error)
                  console.error('An error occurred: ' + error)
                } else {
                  res.json({
                    message: 'success',
                    userToken: results,
                  })
                }
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No account found',
        })
      }
    }
  })
})

router.post('/admins/delete', checkAuth, (req, res) => {
  con.query("select * from users where userid = ? where type = 'Admin'", [req.body.userid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from users where userid = ?', [req.body.userid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No account found',
        })
      }
    }
  })
})

/* Teams */
router.post('/teams/all', checkAuth, (req, res) => {
  var comp = req.body.comp
  var searchtxt = comp !== '' ? ' and competitions.id = "' + comp + '" ' : ''
  con.query(
    'select teams.*, competitions.name as compname from teams LEFT JOIN competitions ON teams.competition = competitions.id where 1 ' +
      searchtxt +
      ' order by ' +
      (req.body.comp === '' ? 'competition asc,' : '') +
      ' teams.name asc',
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/teams/get', checkAuth, (req, res) => {
  con.query(
    "SELECT teams.*, competitions.name as compname from teams LEFT JOIN competitions ON teams.competition = competitions.id where teams.id = ? and teams.status = 'Active'",
    [req.body.teamid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/teams/matches', checkAuth, (req, res) => {
  con.query(
    'SELECT matches.*, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.id as competitionId FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and (matches.team1 = ? OR matches.team2 = ?) order by matches.date asc',
    [req.body.teamid, req.body.teamid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/teams/switch', checkAuth, (req, res) => {
  con.query('select * from teams where id = ?', [req.body.team], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          'update teams set competition=? where id = ?',
          [results[0].competition == 1 ? 2 : 1, req.body.team],
          (error, results2) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              res.json({
                message: 'success',
                result: results2,
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/teams/create', checkAuth, upload.single('file'), (req, res) => {
  const players = JSON.parse(req.body.players || JSON.stringify([]))
  const logoPath = req.file ? req.file.path : null
  con.query(
    'INSERT INTO teams (name, status, competition, logo) VALUES (?,?,?,?)',
    [req.body.name, req.body.status ? 'Active' : 'Inactive', req.body.competition, logoPath],
    (error, teamResult) => {
      if (error) {
        res.status(500).json('Error starting transaction: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        if (teamResult.affectedRows) {
          const teamId = teamResult.insertId
          if (players.length > 0) {
            for (const player of players) {
              const playerId = crypto.randomBytes(16).toString('hex')
              con.query(
                'INSERT INTO players (playerid, team, name, position) VALUES (?,?,?,?)',
                [playerId, teamId, player.name, player.position],
                (error2, playersResult) => {
                  if (error2) {
                    res.status(500).json('Error starting transaction: ' + error)
                    console.error('An error occurred: ' + error)
                  } else {
                    if (playersResult.affectedRows) {
                      res.json({
                        message: 'success',
                        result: playersResult,
                      })
                    }
                  }
                }
              )
            }
          } else {
            res.json({
              message: 'success',
              result: teamResult,
            })
          }
        }
      }
    }
  )
})
/* Matches */

router.post('/matches/matchdays/all', checkAuth, (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and matches.status = "' + req.body.statusfilter + '" ' : ''
  let comp = req.body.competition
  let response = {
    matchdays: null,
    currentmatchday: null,
    currentmatchdays: null,
  }
  con.query(
    'SELECT DISTINCT(matchday) as matchday from matches where competition = ? and matchday IS NOT NULL and matchday != "" and (hidden IS NULL OR hidden != 1) order by matchday asc',
    [comp],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        response.matchdays = results
        con.query(
          "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM `matches` LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where matches.competition = ? and (matches.hidden IS NULL OR matches.hidden != 1) and matches.matchday = (SELECT matchday FROM `matches` where competition = ? and (hidden IS NULL OR hidden != 1) and date >= CURDATE() order by date asc limit 1) order by matches.date asc",
          [comp, comp],
          (error, results2) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              response.currentmatchdays = results2

              res.json({
                message: 'success',
                result: response,
              })
            }
          }
        )
      }
    }
  )
})

router.post('/matches/matchdays/matches', checkAuth, (req, res) => {
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and matchday = ? and (matches.hidden IS NULL OR matches.hidden != 1) order by matches.date asc",
    [req.body.matchday],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

// New endpoint to get distinct matchdays as array
router.post('/matches/matchdays/distinct', checkAuth, (req, res) => {
  const { competition } = req.body

  let query =
    'SELECT DISTINCT(matchday) as matchday FROM matches WHERE matchday IS NOT NULL AND matchday != "" AND (hidden IS NULL OR hidden != 1)'
  let params = []

  if (competition) {
    query += ' AND competition = ?'
    params.push(competition)
  }

  query += ' ORDER BY matchday ASC'

  con.query(query, params, (error, results) => {
    if (error) {
      res.status(500).json('An error occurred: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      // Extract just the matchday values as an array
      const matchdays = results.map((row) => row.matchday)

      res.json({
        message: 'success',
        result: matchdays,
      })
    }
  })
})

router.post('/matches/all', checkAuth, (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and matches.status = "' + req.body.statusfilter + '" ' : ''
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and (matches.hidden IS NULL OR matches.hidden != 1) " +
      searchtxt +
      ' order by matches.date asc',
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matches/recent', checkAuth, (req, res) => {
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and (matches.hidden IS NULL OR matches.hidden != 1) and matches.date >= CURDATE() order by matches.date asc limit 10",
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matches/get', checkAuth, (req, res) => {
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where matches.matchid = ? and (matches.hidden IS NULL OR matches.hidden != 1)",
    [req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matches/add', checkAuth, (req, res) => {
  const matchid = crypto.randomBytes(10).toString('hex')
  con.query(
    'INSERT INTO matches (matchid, competition, team1, team2, date, time, matchday, status) VALUES (?,?,?,?,?,?,?,?)',
    [
      matchid,
      req.body.competition,
      req.body.team1,
      req.body.team2,
      req.body.date,
      req.body.time,
      req.body.matchday,
      req.body.status,
    ],
    (error, results) => {
      if (error) {
        res.status(500).json('Error starting transaction: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matches/review', checkAuth, (req, res) => {
  con.query(
    "select * from matches where matchid = ? and status = 'Under Review'",
    [req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        if (results.length > 0) {
          const username = results[0].name
          const usersemail = results[0].email

          con.query(
            'update matches set status = ?, reviewnote=? where matchid = ?',
            [
              req.body.reviewaction === 'Approved' ? 'Active' : req.body.reviewaction,
              req.body.reviewnote,
              req.body.matchid,
            ],
            (error, results) => {
              if (error) {
                res.status(500).json('An error occurred: ' + error)
                console.error('An error occurred: ' + error)
              } else {
                res.json({
                  message: 'success',
                })
                // Send reset password email with the reset link
                /*
                                      const emailName = username;
                                      const emailSubject = `Account Verified Successfully`;
                                      const emailMessage = `We are delighted to inform you that your account with <b>${sitename}</b> has been successfully verified. Congratulations!
                                      <br><br>
                                      You can now enjoy full access to our services and explore all the features and benefits we offer.
                                      <br><br>
                                      Should you have any questions or need assistance, please don't hesitate to reach out to our support team at <b>help@protectartists.com</b>.
                                      <br><br>
                                      Thank you for choosing <b>${sitename}</b>. We look forward to serving you!.
                                      `;

                                      sendEmail(usersemail, emailSubject, emailName, emailMessage)
                                      */
              }
            }
          )
        } else {
          res.json({
            message: 'Invalid request',
          })
        }
      }
    }
  )
})

router.post('/matches/update', checkAuth, (req, res) => {
  con.query('select * from matches where matchid = ?', [req.body.matchid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          'update matches set competition=?, team1=?, team2=?, date=?, time=?, matchday=?, status=? where matchid = ?',
          [
            req.body.competition,
            req.body.team1,
            req.body.team2,
            req.body.date,
            req.body.time,
            req.body.matchday,
            req.body.status,
            req.body.matchid,
          ],
          (error, results) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              res.json({
                message: 'success',
                result: results,
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/matches/delete', checkAuth, (req, res) => {
  con.query('select * from matches where matchid = ?', [req.body.matchid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from matches where matchid = ?', [req.body.matchid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/matches/websites', checkAuth, (req, res) => {
  con.query(
    'SELECT linkwebsites.*, (select sum(spectators) from matchspectators where matchspectators.matchid = ? and matchspectators.website = linkwebsites.id) as totalspectators from linkwebsites',
    [req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matches/specwebsites', checkAuth, (req, res) => {
  con.query(
    'SELECT linkwebsites.*, (select sum(spectators) from matchspectators where matchspectators.matchid = ? and matchspectators.website = linkwebsites.id) as totalspectators from linkwebsites where spectators = 1',
    [req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matches/websites/update', checkAuth, (req, res) => {
  const { matchid, spectators } = req.body

  // Start a transaction
  con.beginTransaction((err) => {
    if (err) {
      return res.status(500).json('Error starting transaction: ' + err.message)
    }

    // Prepare SQL for updating spectators
    const query =
      'INSERT INTO matchspectators (matchid, website, spectators) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE spectators = VALUES(spectators)'
    // Execute multiple updates
    Object.entries(spectators).forEach(([websiteId, count], index, array) => {
      con.query(query, [matchid, websiteId, count], (error) => {
        if (error) {
          return con.rollback(() => {
            console.error('An error occurred: ' + error)
            res.status(500).json('Error updating data: ' + error.message)
          })
        }

        // If last item in array, commit transaction
        if (index === array.length - 1) {
          con.commit((err) => {
            if (err) {
              return con.rollback(() => {
                res.status(500).json('Error committing transaction: ' + err.message)
              })
            }
            res.json({
              message: 'success',
              result: 'All updates completed successfully.',
            })
          })
        }
      })
    })
  })
})

/* Link Categories */

router.post('/linkcategories/all', checkAuth, (req, res) => {
  var typef = req.body.type !== '' ? ' and matchlinks.type = "' + req.body.type + '" ' : ''
  con.query(
    'SELECT linkcategories.*, (select count(*) from matchlinks where matchlinks.matchid = ? and matchlinks.category = linkcategories.id ' +
      typef +
      ") as totallinks, (select count(*) from matchlinks where matchlinks.matchid = ? and matchlinks.type = 'Live') as totallivelinks, (select count(*) from matchlinks where matchlinks.matchid = ? and matchlinks.type = 'Highlight') as totalhighlightlinks, (select count(*) from matchlinks where matchlinks.matchid = ? and matchlinks.type = 'Google') as totalgooglelinks from linkcategories order by linkcategories.name asc",
    [req.body.matchid, req.body.matchid, req.body.matchid, req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/linkcategories/get', checkAuth, (req, res) => {
  con.query(
    'SELECT linkcategories.* from linkcategories where linkcategories.id = ?',
    [req.body.catid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/linkcategories/add', checkAuth, (req, res) => {
  con.query('INSERT INTO linkcategories (name) VALUES (?)', [req.body.name], (error, results) => {
    if (error) {
      res.status(500).json('Error starting transaction: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/linkcategories/update', checkAuth, (req, res) => {
  con.query('select * from linkcategories where id = ?', [req.body.catid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          'update linkcategories set name=? where id = ?',
          [req.body.name, req.body.catid],
          (error, results) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              res.json({
                message: 'success',
                result: results,
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/linkcategories/delete', checkAuth, (req, res) => {
  con.query('select * from linkcategories where id = ?', [req.body.catid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from linkcategories where id = ?', [req.body.catid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

/* Websites Links */

router.post('/linkwebsites/all', checkAuth, (req, res) => {
  var typef = req.body.type !== '' ? ' and matchlinks.type = "' + req.body.type + '" ' : ''
  con.query('SELECT linkwebsites.* from linkwebsites order by linkwebsites.name asc', (error, results) => {
    if (error) {
      res.status(500).json('An error occurred: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/linkwebsites/get', checkAuth, (req, res) => {
  con.query('SELECT linkwebsites.* from linkwebsites where linkwebsites.id = ?', [req.body.webid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/linkwebsites/add', checkAuth, (req, res) => {
  con.query('INSERT INTO linkwebsites (name) VALUES (?)', [req.body.name], (error, results) => {
    if (error) {
      res.status(500).json('Error starting transaction: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/linkwebsites/update', checkAuth, (req, res) => {
  con.query('select * from linkwebsites where id = ?', [req.body.webid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('update linkwebsites set link=? where id = ?', [req.body.link, req.body.webid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
              result: results,
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/linkwebsites/delete', checkAuth, (req, res) => {
  con.query('select * from linkwebsites where id = ?', [req.body.webid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from linkwebsites where id = ?', [req.body.webid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

/* Matchday Data */

router.post('/matchdaydata/all', checkAuth, (req, res) => {
  const currentYear = new Date().getFullYear()
  //    var typef = req.body.type !== "" ? ' and matchlinks.type = "' + req.body.type + '" ' : "";
  var competition = req.body.competition
  con.query(
    'SELECT DISTINCT(matches.matchday) AS matchDay, matchdaydata.* FROM matches LEFT JOIN matchdaydata ON matches.matchday = matchdaydata.matchday AND matches.competition = matchdaydata.competition AND matchdaydata.year = ? WHERE matches.competition = ? AND matches.matchday IS NOT NULL AND matches.matchday != "" ORDER BY matches.matchday ASC;',
    [currentYear, competition],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matchdaydata/get', checkAuth, (req, res) => {
  const currentYear = new Date().getFullYear()
  con.query(
    'SELECT matchdaydata.* from matchdaydata where matchdaydata.matchday = ? and matchdaydata.competition = ? and matchdaydata.year = ?',
    [req.body.matchday, req.body.competition, currentYear],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matchdaydata/getclosure', checkAuth, (req, res) => {
  const currentYear = new Date().getFullYear()
  con.query(
    'select linkwebsites.*, (select (rate) from matchdayclosure where matchdayclosure.platform = linkwebsites.id and matchdayclosure.matchday = ? and matchdayclosure.competition = ? and matchdayclosure.year = ?) as rate, (select (highlightrate) from matchdayclosure where matchdayclosure.platform = linkwebsites.id and matchdayclosure.matchday = ? and matchdayclosure.competition = ? and matchdayclosure.year = ?) as highlightrate, (select (time) from matchdayclosure where matchdayclosure.platform = linkwebsites.id and matchdayclosure.matchday = ? and matchdayclosure.competition = ? and matchdayclosure.year = ?) as time, (select (highlighttime) from matchdayclosure where matchdayclosure.platform = linkwebsites.id and matchdayclosure.matchday = ? and matchdayclosure.competition = ? and matchdayclosure.year = ?) as highlighttime from linkwebsites',
    [
      req.body.matchday,
      req.body.competition,
      currentYear,
      req.body.matchday,
      req.body.competition,
      currentYear,
      req.body.matchday,
      req.body.competition,
      currentYear,
      req.body.matchday,
      req.body.competition,
      currentYear,
    ],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/matchdaydata/add', checkAuth, (req, res) => {
  con.query('INSERT INTO matchdaydata (name) VALUES (?)', [req.body.name], (error, results) => {
    if (error) {
      res.status(500).json('Error starting transaction: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/matchdaydata/update', checkAuth, (req, res) => {
  const {
    matchday,
    competition,
    twitterNotified,
    twitterSuspended,
    tiktokNotified,
    tiktokSuspended,
    telegramNotified,
    telegramSuspended,
    telegramImpacted,
    discordSuspended,
    snapchatNotified,
    closureRates,
    highlightRates,
    closureTimes,
    highlightTimes,
  } = req.body

  const currentYear = new Date().getFullYear()

  const insertOrUpdateMatchdayData = `
        INSERT INTO matchdaydata (matchday, competition, year, accnotifiedtwitter, accsuspendedtwitter, accnotifiedtiktok, accsuspendedtiktok, accnotifiedtelegram, accsuspendedtelegram, accsuspendeddiscord, accnotifiedsnapchat, membersinspactedtelegram) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        accnotifiedtwitter = VALUES(accnotifiedtwitter), 
        accsuspendedtwitter = VALUES(accsuspendedtwitter), 
        accnotifiedtiktok = VALUES(accnotifiedtiktok), 
        accsuspendedtiktok = VALUES(accsuspendedtiktok), 
        accnotifiedtelegram = VALUES(accnotifiedtelegram), 
        accsuspendedtelegram = VALUES(accsuspendedtelegram), 
        accsuspendeddiscord = VALUES(accsuspendeddiscord), 
        accnotifiedsnapchat = VALUES(accnotifiedsnapchat), 
        membersinspactedtelegram = VALUES(membersinspactedtelegram)`

  const insertOrUpdateMatchdayClosure = `
        INSERT INTO matchdayclosure (matchday, competition, platform, rate, highlightrate, time, highlighttime, year) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        rate = VALUES(rate),
        highlightrate = VALUES(highlightrate),
        time = VALUES(time),
        highlighttime = VALUES(highlighttime)`

  const closureValues = Object.entries(closureRates)
    .filter(([platform, rate]) => rate !== null)
    .map(([platform, rate]) => [
      matchday,
      competition,
      platform,
      rate || 0,
      highlightRates[platform] || 0,
      closureTimes[platform] || '-',
      highlightTimes[platform] || '-',
      currentYear,
    ])

  con.beginTransaction((err) => {
    if (err) {
      return res.status(500).json('Transaction initiation error: ' + err)
    }

    con.query(
      insertOrUpdateMatchdayData,
      [
        matchday,
        competition,
        currentYear,
        twitterNotified,
        twitterSuspended,
        tiktokNotified,
        tiktokSuspended,
        telegramNotified,
        telegramSuspended,
        discordSuspended,
        snapchatNotified,
        telegramImpacted,
      ],
      (error, results) => {
        if (error) {
          return con.rollback(() => {
            res.status(500).json('Error executing query: ' + error)
            console.error('Error executing MySQL query: ' + error)
          })
        }

        if (closureValues.length > 0) {
          const insertOrUpdateClosurePromises = closureValues.map((value) => {
            return new Promise((resolve, reject) => {
              con.query(insertOrUpdateMatchdayClosure, value, (error, results) => {
                if (error) {
                  reject(error)
                } else {
                  resolve(results)
                }
              })
            })
          })

          Promise.all(insertOrUpdateClosurePromises)
            .then((closureResults) => {
              con.commit((err) => {
                if (err) {
                  return con.rollback(() => {
                    res.status(500).json('Transaction commit error: ' + err)
                  })
                }

                res.json({
                  message: 'success',
                  result: results,
                })
              })
            })
            .catch((error) => {
              con.rollback(() => {
                res.status(500).json('Error executing closure queries: ' + error)
                console.error('Error executing MySQL query: ' + error)
              })
            })
        } else {
          con.commit((err) => {
            if (err) {
              return con.rollback(() => {
                res.status(500).json('Transaction commit error: ' + err)
              })
            }

            res.json({
              message: 'success',
              result: results,
            })
          })
        }
      }
    )
  })
})

router.post('/matchdaydata/delete', checkAuth, (req, res) => {
  con.query('select * from matchdaydata where id = ?', [req.body.webid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from matchdaydata where id = ?', [req.body.webid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

/* Match Links */

router.post('/matchlinks/all', checkAuth, async (req, res) => {
  try {
    let results = {
      matchlinks: 0,
      totallive: 0,
      totalhighlights: 0,
      totalgoogle: 0,
      totalwebsites: [],
      totalspectators: 0,
    }

    const matchlinks = await queryAsync('SELECT * from matchlinks where matchid = ? and type = ?', [
      req.body.matchid,
      req.body.type,
    ])
    results.matchlinks = matchlinks

    const totallive = await queryAsync("SELECT count(*) as count from matchlinks where type = 'Live' and matchid = ?", [
      req.body.matchid,
    ])
    results.totallive = totallive[0].count

    const totalhighlights = await queryAsync(
      "SELECT count(*) as count from matchlinks where type = 'Highlight' and matchid = ?",
      [req.body.matchid]
    )
    results.totalhighlights = totalhighlights[0].count

    const totalgoogle = await queryAsync(
      "SELECT count(*) as count from matchlinks where type = 'Google' and matchid = ?",
      [req.body.matchid]
    )
    results.totalgoogle = totalgoogle[0].count

    const totalspectators = await queryAsync('SELECT sum(spectators) as count from matchspectators where matchid = ?', [
      req.body.matchid,
    ])
    results.totalspectators = totalspectators[0].count

    //        const totalwebsites = await queryAsync("SELECT lw.*, (SELECT COUNT(*) FROM matchlinks ml WHERE (ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 1), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 2), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 3), ',', -1)), '%')) and ml.matchid = ?) AS total FROM linkwebsites lw", [req.body.matchid]);
    //        results.totalwebsites = totalwebsites;

    const linkwebsites = await queryAsync('SELECT * FROM linkwebsites')

    const totalwebsites = await Promise.all(
      linkwebsites.map(async (lw) => {
        let domains = lw.link.split(',').map((domain) => domain.trim().replace(/^https?:\/\//, ''))
        let likeConditions = domains.map((domain) => `ml.link LIKE CONCAT('%', '${domain}', '%')`).join(' OR ')

        const totalCountQuery = `
                SELECT COUNT(*) as total 
                FROM matchlinks ml 
                WHERE (${likeConditions}) AND ml.matchid = ?
            `
        const totalCountResult = await queryAsync(totalCountQuery, [req.body.matchid])

        return {
          ...lw,
          total: totalCountResult[0].total,
        }
      })
    )

    results.totalwebsites = totalwebsites

    res.json({
      message: 'success',
      result: results,
    })
  } catch (error) {
    console.error('Error fetching stats:', error)
    res.status(500).json({
      message: 'Error fetching stats',
    })
  }
})

router.post('/matchlinks/websites', checkAuth, async (req, res) => {
  try {
    let results = {
      matchlinks: 0,
      totallive: 0,
      totalhighlights: 0,
      totalgoogle: 0,
    }

    const matchlinks = await queryAsync('SELECT * from matchlinks where matchid = ? and type = ?', [
      req.body.matchid,
      req.body.type,
    ])
    results.matchlinks = matchlinks

    const totallive = await queryAsync("SELECT count(*) as count from matchlinks where type = 'Live' and matchid = ?", [
      req.body.matchid,
    ])
    results.totallive = totallive[0].count

    const totalhighlights = await queryAsync(
      "SELECT count(*) as count from matchlinks where type = 'Highlight' and matchid = ?",
      [req.body.matchid]
    )
    results.totalhighlights = totalhighlights[0].count

    const totalgoogle = await queryAsync(
      "SELECT count(*) as count from matchlinks where type = 'Google' and matchid = ?",
      [req.body.matchid]
    )
    results.totalgoogle = totalgoogle[0].count

    res.json({
      message: 'success',
      result: results,
    })
  } catch (error) {
    console.error('Error fetching stats:', error)
    res.status(500).json({
      message: 'Error fetching stats',
    })
  }
})

router.post('/matchlinks/add', checkAuth, (req, res) => {
  let { input, matchid, type, category } = req.body
  let links = input.split('\n').filter((link) => link.trim() !== '')

  if (links.length > 0) {
    let sqlInsert = 'INSERT IGNORE  INTO matchlinks (matchid, type, link, domain) VALUES ?'
    let values = links.map((link) => {
      const parsedUrl = url.parse(link.trim())
      let domain = parsedUrl.hostname?.replace(/^www\./, '') // Remove 'www.' prefix if it exists
      return [matchid, type, link.trim(), domain]
    })

    con.query(sqlInsert, [values], (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
        //                res.json({
        //                    message: "success",
        //                    result: results,
        //                });
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    })
  } else {
    res.status(400).json('No links provided')
  }
})

router.post('/matchlinks/delete', checkAuth, (req, res) => {
  con.query('select * from matchlinks where id = ?', [req.body.id], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from matchlinks where id = ?', [req.body.id], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

/* Players */

router.post('/players/all', checkAuth, (req, res) => {
  //    var typef = req.body.type !== "" ? ' and matchlinks.type = "' + req.body.type + '" ' : "";
  con.query(
    "SELECT * from players where team = ? order by FIELD(position, 'Striker', 'Midfielder', 'Defender', 'Goalkeeper')",
    [req.body.team],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/players/get', checkAuth, (req, res) => {
  con.query('SELECT players.* from players where players.playerid = ?', [req.body.playerid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred: ' + error)
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/players/update', checkAuth, (req, res) => {
  con.query('select * from players where playerid = ?', [req.body.playerid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          'update players set name=?,position=? where playerid = ?',
          [req.body.name, req.body.position, req.body.playerid],
          (error, results) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              res.json({
                message: 'success',
                result: results,
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/players/switch', checkAuth, (req, res) => {
  con.query('select * from players where playerid = ?', [req.body.playerid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query(
          'update players set team=? where playerid = ?',
          [req.body.team, req.body.playerid],
          (error, results) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              res.json({
                message: 'success',
                result: results,
              })
            }
          }
        )
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

router.post('/players/add', checkAuth, (req, res) => {
  const { team, name, position } = req.body
  const playerid = crypto.randomBytes(16).toString('hex')
  con.query(
    'INSERT INTO players (playerid,team,name,position) VALUES (?,?,?,?)',
    [playerid, team, name, position],
    (error, results) => {
      if (error) {
        res.status(500).json('Error starting transaction: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/players/delete', checkAuth, (req, res) => {
  con.query('select * from players where playerid = ?', [req.body.playerid], (error, results) => {
    if (error) {
      res.status(500).json('An error occurred:' + error)
      console.error('An error occurred:' + error)
    } else {
      if (results.length > 0) {
        con.query('delete from players where playerid = ?', [req.body.playerid], (error, results) => {
          if (error) {
            res.status(500).json('An error occurred: ' + error)
            console.error('An error occurred: ' + error)
          } else {
            res.json({
              message: 'success',
            })
          }
        })
      } else {
        res.json({
          message: 'No record found',
        })
      }
    }
  })
})

/* Score */

/*
router.post("/score/add", (req, res) => {

    let values = [];
    if (team1scorer && team1scorer.length > 0) {
        team1scorer.forEach(playerid => {
            values.push([matchid, results.team1, playerid]);
        });
    }
    if (team2scorer && team2scorer.length > 0) {
        team2scorer.forEach(playerid => {
            values.push([matchid, results.team2, playerid]);
        });
    }

    con.query("select * from matches where matchid = ?", [req.body.matchid], (error, results) => {
        if (error) {
            res.status(500).json("An error occurred:" + error);
            console.error("An error occurred:" + error);
        } else {
            if (results.length > 0) {
                con.query("update matches set team1score=?,team2score=? where matchid = ?", [req.body.team1score, req.body.team2score, req.body.matchid], (error, results2) => {
                    if (error) {
                        res.status(500).json("An error occurred: " + error);
                        console.error("An error occurred: " + error);
                    } else {
                        con.query("delete from scorers where matchid = ?", [req.body.matchid], (error, results3) => {
                            if (error) {
                                res.status(500).json("An error occurred: " + error);
                                console.error("An error occurred: " + error);
                            } else {

                                if (values.length > 0) {
                                    const sql = "INSERT INTO scorers (matchid, teamid, playerid) VALUES ?";
                                    con.query(sql, [values], (error, results) => {
                                        if (error) {
                                            res.status(500).json("An error occurred: " + error);
                                            console.error("An error occurred: " + error);
                                        } else {
                                            res.json({
                                                message: "success",
                                                result: results,
                                            });
                                        }
                                    });
                                } else {
                                    res.status(400).json("No scorers provided");
                                }

                            }
                        });
                    }
                });
            } else {
                res.json({
                    message: "No record found",
                });
            }
        }
    });
});
*/

router.post('/score/add', checkAuth, async (req, res) => {
  const { matchid, team1scorer, team2scorer, team1score, team2score } = req.body

  try {
    con.beginTransaction(async (err) => {
      if (err) {
        return res.status(500).json('Error starting transaction: ' + err.message)
      }

      const matchResults = await queryAsync('SELECT * FROM matches WHERE matchid = ?', [matchid])
      if (matchResults.length === 0) {
        return con.rollback(() => {
          res.status(404).json({
            message: 'No record found',
          })
        })
      }

      const match = matchResults[0]

      await queryAsync('UPDATE matches SET team1score = ?, team2score = ? WHERE matchid = ?', [
        team1score,
        team2score,
        matchid,
      ])
      await queryAsync('DELETE FROM scorers WHERE matchid = ?', [matchid])

      let values = []
      if (team1scorer && team1scorer.length) {
        values.push(...team1scorer.map((playerid) => [matchid, match.team1, playerid]))
      }
      if (team2scorer && team2scorer.length) {
        values.push(...team2scorer.map((playerid) => [matchid, match.team2, playerid]))
      }

      if (values.length > 0) {
        await queryAsync('INSERT INTO scorers (matchid, teamid, playerid) VALUES ?', [values])
      }

      con.commit((err) => {
        if (err) {
          return con.rollback(() => {
            res.status(500).json('Error committing transaction: ' + err.message)
          })
        }

        return res.json({
          message: 'success',
        })
      })
    })
  } catch (error) {
    return con.rollback(() => {
      res.status(404).json({
        message: 'An error occurred',
        error: error,
      })
    })
  }
})

router.post('/score/teamscorers', checkAuth, (req, res) => {
  //    var typef = req.body.type !== "" ? ' and matchlinks.type = "' + req.body.type + '" ' : "";
  con.query(
    'SELECT players.name as playername, players.team as origteamid from scorers LEFT JOIN players ON scorers.playerid = players.playerid where scorers.teamid = ? and scorers.matchid = ?',
    [req.body.team, req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

/* Overview */

router.post('/overview/all', checkAuth, (req, res) => {
  var competition = req.body.competition
  var dateFilter = ''
  if (req.body.date.startDate && req.body.date.endDate) {
    dateFilter = " AND matches.date BETWEEN '" + req.body.date.startDate + "' AND '" + req.body.date.endDate + "' "
  }

  var competitionf = competition !== '' ? " AND matches.competition = '" + competition + "'" : ''

  con.query(
    `SELECT linkcategories.*, (SELECT COUNT(*) FROM matchlinks INNER JOIN matches ON matchlinks.matchid = matches.matchid WHERE matchlinks.category = linkcategories.id ${competitionf} ${dateFilter}) AS totallinks, (SELECT COUNT(*) FROM matchlinks INNER JOIN matches ON matchlinks.matchid = matches.matchid WHERE matchlinks.type = 'Live' AND matchlinks.category = linkcategories.id ${competitionf} ${dateFilter}) AS totallivelinks, (SELECT COUNT(*) FROM matchlinks INNER JOIN matches ON matchlinks.matchid = matches.matchid WHERE matchlinks.type = 'Highlight' AND matchlinks.category = linkcategories.id ${competitionf} ${dateFilter}) AS totalhighlightlinks, (SELECT COUNT(*) FROM matchlinks INNER JOIN matches ON matchlinks.matchid = matches.matchid WHERE matchlinks.type = 'Google' AND matchlinks.category = linkcategories.id ${competitionf} ${dateFilter}) AS totalgooglelinks FROM linkcategories ORDER BY linkcategories.name ASC`,
    (error, results) => {
      if (error) {
        res.status(500).json({
          message: 'An error occurred',
          error,
        })
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/overview/stats', checkAuth, (req, res) => {
  const competition = req.body.competition
  const team = req.body.team
  let dateFilter = ''
  if (req.body.date.startDate && req.body.date.endDate) {
    dateFilter = ` AND m.date BETWEEN "${req.body.date.startDate}" AND "${req.body.date.endDate}"`
  }

  const competitionFilter = competition !== '' ? ` AND m.competition = '${competition}'` : ''
  const teamFilter = team !== '' ? ` AND (m.team1 = '${team}' OR m.team2 = '${team}')` : ''

  const whereClause = `WHERE ml.link IS NOT NULL ${competitionFilter} ${dateFilter} ${teamFilter}`

  const teamLinks =
    team !== ''
      ? `
        , (SELECT COUNT(DISTINCT ml.id) 
           FROM matchlinks ml 
           JOIN matches m ON ml.matchid = m.matchid 
           ${whereClause} AND m.team1 = '${team}') AS teamhomelinks
        , (SELECT COUNT(DISTINCT ml.id) 
           FROM matchlinks ml 
           JOIN matches m ON ml.matchid = m.matchid 
           ${whereClause} AND m.team2 = '${team}') AS teamawaylinks 
    `
      : ''

  const query = `
        WITH links AS (
            SELECT DISTINCT ml.id, ml.type, ml.link 
            FROM matchlinks ml 
            JOIN matches m ON ml.matchid = m.matchid 
            ${whereClause}
        )
        SELECT 
            (SELECT COUNT(*) FROM links) AS totallinks,
            (SELECT COUNT(*) FROM links WHERE type = 'Live') AS totallivelinks,
            (SELECT COUNT(*) FROM links WHERE type = 'Highlight') AS totalhighlightlinks,
            (SELECT COUNT(*) FROM links WHERE type = 'Google') AS totalgooglelinks,
            (SELECT COUNT(DISTINCT m.id) 
             FROM matches m 
             WHERE 1 ${competitionFilter} ${dateFilter} ${teamFilter}) AS totalmatchdays
            ${teamLinks}
    `

  con.query(query, (error, results) => {
    if (error) {
      res.status(500).json({
        message: 'An error occurred',
        error,
      })
      console.error('An error occurred: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/overview/domain', checkAuth, async (req, res) => {
  try {
    var competition = req.body.competition
    var team = req.body.team
    var dateFilter = ''

    // Check if both startDate and endDate are provided
    if (req.body.date && req.body.date.startDate !== '' && req.body.date.endDate !== '') {
      dateFilter = ` AND m.date BETWEEN "${req.body.date.startDate}" AND "${req.body.date.endDate}"`
    }

    var competitionFilter = competition !== '' ? ` AND m.competition = "${competition}"` : ''
    var teamFilter = team !== '' ? ` AND (m.team1 = "${team}" OR m.team2 = "${team}")` : ''

    var whereClause = `WHERE ml.link IS NOT NULL ${competitionFilter} ${dateFilter} ${teamFilter}`

    // Add team links only if a team is specified
    var teamLinks =
      team !== ''
        ? `, COUNT(DISTINCT CASE WHEN m.team1 = ${team} THEN ml.id END) AS teamhomelinks,
            COUNT(DISTINCT CASE WHEN m.team2 = ${team} THEN ml.id END) AS teamawaylinks`
        : ''

    // Add team links joins only if a team is specified
    // var teamLinksJoins = team !== '' ? `and (m.team1 = 1 OR m.team2 = 1)` : ''
    // ${teamLinksJoins}

    con.query(
      `
            SELECT 
                ml.domain AS name, 
                COUNT(DISTINCT ml.link) AS totallinks, 
                COUNT(DISTINCT CASE WHEN ml.type = 'Live' THEN ml.link END) AS totallivelinks, 
                COUNT(DISTINCT CASE WHEN ml.type = 'Highlight' THEN ml.link END) AS totalhighlightlinks, 
                COUNT(DISTINCT CASE WHEN ml.type = 'Google' THEN ml.link END) AS totalgooglelinks
                ${teamLinks}
            FROM 
                matchlinks ml
            LEFT JOIN 
                matches m ON ml.matchid = m.matchid
            ${whereClause}
            GROUP BY 
                name 
            ORDER BY 
                totallinks DESC`,
      (error, results) => {
        if (error) {
          res.status(500).json('An error occurred: ' + error)
          console.error('An error occurred: ' + error)
        } else {
          res.json({
            message: 'success',
            result: results,
          })
        }
      }
    )
  } catch (error) {
    console.error('An error occurred: ' + error)
    res.status(500).json('An error occurred: ' + error)
  }
})

router.post('/overview/match', checkAuth, (req, res) => {
  var typef = req.body.type !== '' ? ' and matchlinks.type = "' + req.body.type + '" ' : ''
  con.query(
    'SELECT linkcategories.*, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = ? and matchlinks.category = linkcategories.id ' +
      typef +
      ") as totallinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = ? and matchlinks.type = 'Live') as totallivelinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = ? and matchlinks.type = 'Highlight') as totalhighlightlinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = ? and matchlinks.type = 'Google') as totalgooglelinks from linkcategories order by linkcategories.name asc",
    [req.body.matchid, req.body.matchid, req.body.matchid],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

/* Report */

router.post('/reports/matchdays/all', checkAuth, (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and matches.status = "' + req.body.statusfilter + '" ' : ''
  let comp = req.body.competition
  let response = {
    matchdays: null,
    currentmatchday: null,
    currentmatchdays: null,
  }
  con.query(
    'SELECT DISTINCT(matchday) as matchday from matches where competition = ? and matchday IS NOT NULL and matchday != "" and (hidden IS NULL OR hidden != 1) order by matchday asc',
    [comp],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        response.matchdays = results
        con.query(
          "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM `matches` LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where matches.competition = ? and (matches.hidden IS NULL OR matches.hidden != 1) and matches.matchday = (SELECT matchday FROM `matches` where competition = ? and (hidden IS NULL OR hidden != 1) and date >= CURDATE() order by date asc limit 1) order by matches.date asc",
          [comp, comp],
          (error, results2) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              response.currentmatchdays = results2

              res.json({
                message: 'success',
                result: response,
              })
            }
          }
        )
      }
    }
  )
})

router.post('/reports/matchdays/matches', checkAuth, (req, res) => {
  con.query(
    "SELECT matches.*, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid) as totallinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid and type = 'Live') as livelinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid and type = 'Highlight') as highlightlinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid and type = 'Google') as googlelinks, (select SUM(spectators) from matchspectators where matchspectators.matchid = matches.matchid) as totalspectators, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and matchday = ? and matches.competition = ? and (matches.hidden IS NULL OR matches.hidden != 1) order by matches.date asc",
    [req.body.matchday, req.body.competition],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/reports/links/websites', checkAuth, (req, res) => {
  //    con.query("SELECT lw.*, (SELECT SUM(spectators) from matchspectators LEFT JOIN matches ON matchspectators.matchid = matches.matchid where matchspectators.website = lw.id and matches.matchday = ? and matches.competition = ?) as totalspectators, (SELECT COUNT(*) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE (ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 1), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 2), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 3), ',', -1)), '%')) and ml.type = 'Live' and m.matchday = ? and m.competition = ?) AS livelinks, (SELECT COUNT(*) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE (ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 1), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 2), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 3), ',', -1)), '%')) and ml.type = 'Highlight' and m.matchday = ? and m.competition = ?) AS highlightlinks, (SELECT COUNT(*) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE (ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 1), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 2), ',', -1)), '%') OR ml.link LIKE CONCAT('%', TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(lw.link, ',', 3), ',', -1)), '%')) and ml.type = 'Google' and m.matchday = ? and m.competition = ?) AS googlelinks, (SELECT rate from matchdayclosure where matchdayclosure.matchday = ? and matchdayclosure.competition=? and matchdayclosure.platform=lw.id) as rate, (SELECT highlightrate from matchdayclosure where matchdayclosure.matchday = ? and matchdayclosure.competition=? and matchdayclosure.platform=lw.id) as highlightrate, (SELECT time from matchdayclosure where matchdayclosure.matchday = ? and matchdayclosure.competition=? and matchdayclosure.platform=lw.id) as time, (SELECT highlighttime from matchdayclosure where matchdayclosure.matchday = ? and matchdayclosure.competition=? and matchdayclosure.platform=lw.id) as highlighttime FROM linkwebsites lw where lw.spectators = 1", [req.body.matchday, req.body.competition, req.body.matchday, req.body.competition, req.body.matchday, req.body.competition, req.body.matchday, req.body.competition, req.body.matchday, req.body.competition, req.body.matchday, req.body.competition, req.body.matchday, req.body.competition, req.body.matchday, req.body.competition], (error, results) => {
  con.query(
    `SELECT lw.*, 
    (SELECT SUM(spectators) from matchspectators LEFT JOIN matches ON matchspectators.matchid = matches.matchid where matchspectators.website = lw.id and matches.matchday= ? and matches.competition= ?) as totalspectators, 
    (SELECT COUNT(DISTINCT(link)) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE FIND_IN_SET(ml.domain, REPLACE(lw.link, ' ', '')) and m.matchday= ? and m.competition= ?) AS totallinks, 
    (SELECT COUNT(DISTINCT(link)) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE FIND_IN_SET(ml.domain, REPLACE(lw.link, ' ', '')) and ml.type = 'Live' and m.matchday= ? and m.competition= ?) AS livelinks,
    (SELECT COUNT(DISTINCT(link)) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE FIND_IN_SET(ml.domain, REPLACE(lw.link, ' ', '')) and ml.type = 'Highlight' and m.matchday= ? and m.competition= ?) AS highlightlinks,
    (SELECT COUNT(DISTINCT(link)) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE FIND_IN_SET(ml.domain, REPLACE(lw.link, ' ', '')) and ml.type = 'Google' and m.matchday= ? and m.competition= ?) AS googlelinks,
    (SELECT rate from matchdayclosure where matchdayclosure.matchday= ? and matchdayclosure.competition = ? and matchdayclosure.platform=lw.id) as rate, 
    (SELECT highlightrate from matchdayclosure where matchdayclosure.matchday= ? and matchdayclosure.competition = ? and matchdayclosure.platform=lw.id) as highlightrate, 
    (SELECT time from matchdayclosure where matchdayclosure.matchday= ? and matchdayclosure.competition = ? and matchdayclosure.platform=lw.id) as time, 
    (SELECT highlighttime from matchdayclosure where matchdayclosure.matchday= ? and matchdayclosure.competition = ? and matchdayclosure.platform=lw.id) as highlighttime 
    FROM linkwebsites lw;`,
    [
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
      req.body.matchday,
      req.body.competition,
    ],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/reports/matchday/data', checkAuth, (req, res) => {
  const currentYear = new Date().getFullYear()
  con.query(
    'SELECT matchdaydata.* from matchdaydata where matchdaydata.matchday = ? and matchdaydata.competition = ? and matchdaydata.year = ?',
    [req.body.matchday, req.body.competition, currentYear],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  )
})

router.post('/reports/matchday/totals', checkAuth, (req, res) => {
  const currentYear = new Date().getFullYear()
  const matchday = req.body.matchday
  const competition = req.body.competition

  con.query(
    `SELECT ml.domain AS name, COUNT(DISTINCT ml.link) AS totallinks, COUNT(DISTINCT CASE WHEN ml.type = 'Live' THEN ml.link END) AS totallivelinks, COUNT(DISTINCT CASE WHEN ml.type = 'Highlight' THEN ml.link END) AS totalhighlightlinks, COUNT(DISTINCT CASE WHEN ml.type = 'Google' THEN ml.link END) AS totalgooglelinks FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE m.matchday = ? AND m.competition = ? GROUP BY name ORDER BY totallinks DESC;`,
    [matchday, competition],
    (error, matchLinksResults) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        con.query(
          `
            SELECT SUM(ms.spectators) AS totalspectators FROM matchspectators ms LEFT JOIN matches m ON ms.matchid = m.matchid WHERE m.matchday = ? AND m.competition = ?`,
          [matchday, competition],
          (error, spectatorsResults) => {
            if (error) {
              res.status(500).json('An error occurred: ' + error)
              console.error('An error occurred: ' + error)
            } else {
              con.query(
                `
                    SELECT lw.*, (SELECT COUNT(DISTINCT(link)) FROM matchlinks ml LEFT JOIN matches m ON ml.matchid = m.matchid WHERE FIND_IN_SET(ml.domain, REPLACE(lw.link, ' ', '')) and m.matchday=? and m.competition=?) AS totallinks FROM linkwebsites lw where lw.name = 'DDL';`,
                [matchday, competition],
                (error, ddlResults) => {
                  if (error) {
                    res.status(500).json('An error occurred: ' + error)
                    console.error('An error occurred: ' + error)
                  } else {
                    res.json({
                      message: 'success',
                      result: {
                        matchLinksTotals: matchLinksResults,
                        totalSpectators: spectatorsResults[0].totalspectators,
                        totalddl: ddlResults[0].totallinks,
                      },
                    })
                  }
                }
              )
            }
          }
        )
      }
    }
  )
})

/* Dashboard */

router.post('/dashboard/stats', checkAuth, async (req, res) => {
  const userId = req.body.userid
  const userType = req.body.usertype

  if (userType === 'Admin') {
    try {
      let stats = {
        members: 0,
        activemembers: 0,
        matches: 0,
        matchestoday: 0,
        matchestomorrow: 0,
        matchesreview: 0,
      }

      const membersCount = await queryAsync(
        "SELECT count(*) as count from users where type = 'Member' and status <> 'Email'"
      )
      stats.members = membersCount[0].count

      const activeMemberCount = await queryAsync(
        "SELECT count(*) as count from users where type = 'Member' and status = 'Active'"
      )
      stats.activemembers = activeMemberCount[0].count

      const matchesCount = await queryAsync(
        'SELECT count(*) as count from matches where (hidden IS NULL OR hidden != 1)'
      )
      stats.matches = matchesCount[0].count

      const matchestodayCount = await queryAsync(
        'SELECT count(*) as count from matches where date = CURDATE() and (hidden IS NULL OR hidden != 1)'
      )
      stats.matchestoday = matchestodayCount[0].count

      const matchestomorrowCount = await queryAsync(
        'SELECT count(*) as count from matches where date = CURDATE() + INTERVAL 1 DAY and (hidden IS NULL OR hidden != 1)'
      )
      stats.matchestomorrow = matchestomorrowCount[0].count

      const matchesreviewCount = await queryAsync(
        'SELECT COUNT(*) AS count FROM matches WHERE (hidden IS NULL OR hidden != 1) AND EXISTS ( SELECT 1 FROM matchlinks WHERE matchlinks.matchid = matches.matchid )'
      )
      stats.matchesreview = matchesreviewCount[0].count

      res.json({
        message: 'success',
        result: stats,
      })
    } catch (error) {
      console.error('Error fetching stats:', error)
      res.status(500).json({
        message: 'Error fetching stats',
      })
    }
  } else if (userType === 'Member') {
    try {
      let stats = {
        matches: 0,
        matchestoday: 0,
        matchestomorrow: 0,
      }

      const matchesCount = await queryAsync(
        'SELECT count(*) as count from matches where (hidden IS NULL OR hidden != 1)'
      )
      stats.matches = matchesCount[0].count

      const matchestodayCount = await queryAsync(
        'SELECT count(*) as count from matches where date = CURDATE() and (hidden IS NULL OR hidden != 1)'
      )
      stats.matchestoday = matchestodayCount[0].count

      const matchestomorrowCount = await queryAsync(
        'SELECT count(*) as count from matches where date = CURDATE() + INTERVAL 1 DAY and (hidden IS NULL OR hidden != 1)'
      )
      stats.matchestomorrow = matchestomorrowCount[0].count

      res.json({
        message: 'success',
        result: stats,
      })
    } catch (error) {
      console.error('Error fetching stats:', error)
      res.status(500).json({
        message: 'Erreur lors de la récupération des statistiques',
      })
    }
  }
})

/* Competitions */
router.post('/competitions/all', checkAuth, (req, res) => {
  const includeTeams = req.body.includeTeams || false

  if (includeTeams) {
    con.query(
      `SELECT c.*, t.id as team_id, t.name as team_name, t.logo as team_logo, t.status as team_status 
       FROM competitions c 
       LEFT JOIN teams t ON t.competition = c.id 
       ORDER BY c.addedat ASC`,
      (error, results) => {
        if (error) {
          res.status(500).json('Error fetching competitions and teams: ' + error)
          console.error('Error fetching competitions and teams: ' + error)
        } else {
          // Group teams by competition
          const competitions = results.reduce((acc, row) => {
            const competition = acc.find((c) => c.id === row.id)

            if (!competition) {
              // Create new competition entry
              acc.push({
                id: row.id,
                name: row.name,
                status: row.status,
                addedat: row.addedat,
                teams: row.team_id
                  ? [
                      {
                        id: row.team_id,
                        name: row.team_name,
                        logo: row.team_logo,
                        status: row.team_status,
                      },
                    ]
                  : [],
              })
            } else if (row.team_id) {
              // Add team to existing competition
              competition.teams.push({
                id: row.team_id,
                name: row.team_name,
                logo: row.team_logo,
                status: row.team_status,
              })
            }
            return acc
          }, [])

          res.json({
            message: 'success',
            result: competitions,
          })
        }
      }
    )
  } else {
    con.query('select * from competitions order by addedat ASC', (error, results) => {
      if (error) {
        res.status(500).json('Error fetching competitions: ' + error)
        console.error('Error fetching competitions: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    })
  }
})

router.post('/competitions/create', checkAuth, (req, res) => {
  con.query(
    'INSERT INTO competitions (name, status) VALUES (?,?)',
    [req.body.name, req.body.status ? 'Active' : 'Inactive'],
    (error, competitionResult) => {
      if (error) {
        res.status(500).json('Error starting transaction: ' + error)
        console.error('Error starting transaction: ' + error)
      } else {
        if (competitionResult.affectedRows) {
          const competitionId = competitionResult.insertId
          res.json({
            message: 'success',
            result: competitionResult,
          })
        }
      }
    }
  )
})

router.post('/competitions/update', checkAuth, (req, res) => {
  const { id, name, status, competitionId } = req.body

  con.query('UPDATE competitions SET name = ?, status = ? WHERE id = ?', [name, status, competitionId], (error) => {
    if (error) {
      res.status(500).json('Error updating data: ' + error)
      console.error('Error updating data: ' + error)
    } else {
      res.json({
        message: 'success',
        result: 'All updates completed successfully.',
      })
    }
  })
})

router.post('/competitions/delete', checkAuth, (req, res) => {
  con.query('DELETE FROM competitions WHERE id = ?', [req.body.competitionId], (error, results) => {
    if (error) {
      res.status(500).json('Error deleting competition: ' + error)
      console.error('Error deleting competition: ' + error)
    } else {
      if (results.affectedRows === 0) {
        res.status(404).json({
          message: 'Competition not found',
        })
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  })
})

/* File Upload for Broadcasters and VPNs */
router.post('/upload-file', checkAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' })
    }

    const { uploadType } = req.body // 'broadcasters' or 'vpns'
    const filePath = req.file.path
    const fileExtension = path.extname(req.file.originalname).toLowerCase()

    // Check if it's an Excel file
    if (!['.xlsx', '.xls'].includes(fileExtension)) {
      return res.status(400).json({ message: 'Only Excel files (.xlsx, .xls) are supported' })
    }

    // Read the Excel file
    const workbook = xlsx.readFile(filePath)
    const sheetName = workbook.SheetNames[0]
    const worksheet = workbook.Sheets[sheetName]
    const data = xlsx.utils.sheet_to_json(worksheet, { header: 1 })

    // Extract names from the first column (skip header if exists)
    let names = []
    if (data.length > 0) {
      // Check if first row is a header (contains 'name' or similar)
      const firstRow = data[0][0] ? data[0][0].toString().toLowerCase() : ''
      const startIndex =
        firstRow.includes('name') || firstRow.includes('vpn') || firstRow.includes('broadcaster') ? 1 : 0

      names = data
        .slice(startIndex)
        .map((row) => row[0])
        .filter((name) => name && name.toString().trim() !== '')
        .map((name) => name.toString().trim())
    }

    if (names.length === 0) {
      return res.status(400).json({ message: 'No valid data found in the file' })
    }

    // Determine table and clear existing data
    const tableName = uploadType === 'broadcasters' ? 'broadcasters' : 'vpns'

    // Clear existing data
    await queryAsync(`DELETE FROM ${tableName}`)

    // Insert new data
    if (names.length > 0) {
      const values = names.map((name) => [name])
      const query = `INSERT INTO ${tableName} (name) VALUES ?`

      await queryAsync(query, [values])
    }

    // Clean up uploaded file
    fs.unlink(filePath, (err) => {
      if (err) console.error('Error deleting uploaded file:', err)
    })

    res.json({
      message: 'success',
      result: {
        uploaded: names.length,
        type: uploadType,
        names: names,
      },
    })
  } catch (error) {
    console.error('Error processing file upload:', error)
    res.status(500).json({ message: 'Error processing file: ' + error.message })
  }
})

/* Broadcasters */
router.post('/broadcasters/get', checkAuth, (req, res) => {
  con.query('SELECT * FROM broadcasters ORDER BY name ASC', (error, results) => {
    if (error) {
      res.status(500).json('Error fetching broadcasters: ' + error)
      console.error('Error fetching broadcasters: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/broadcasters/save', checkAuth, (req, res) => {
  const { broadcasters } = req.body

  // First, clear existing broadcasters
  con.query('DELETE FROM broadcasters', (deleteError) => {
    if (deleteError) {
      res.status(500).json('Error clearing broadcasters: ' + deleteError)
      console.error('Error clearing broadcasters: ' + deleteError)
      return
    }

    // Then insert new broadcasters
    if (broadcasters && broadcasters.length > 0) {
      const values = broadcasters.map((name) => [name])
      const query = 'INSERT INTO broadcasters (name) VALUES ?'

      con.query(query, [values], (insertError, results) => {
        if (insertError) {
          res.status(500).json('Error saving broadcasters: ' + insertError)
          console.error('Error saving broadcasters: ' + insertError)
        } else {
          res.json({
            message: 'success',
            result: results,
          })
        }
      })
    } else {
      res.json({
        message: 'success',
        result: { message: 'No broadcasters to save' },
      })
    }
  })
})

router.post('/broadcasters/delete', checkAuth, (req, res) => {
  const { id } = req.body

  con.query('DELETE FROM broadcasters WHERE id = ?', [id], (error, results) => {
    if (error) {
      res.status(500).json('Error deleting broadcaster: ' + error)
      console.error('Error deleting broadcaster: ' + error)
    } else {
      if (results.affectedRows === 0) {
        res.status(404).json({
          message: 'Broadcaster not found',
        })
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  })
})

router.post('/broadcasters/add', checkAuth, (req, res) => {
  const { name } = req.body

  con.query('INSERT INTO broadcasters (name) VALUES (?)', [name], (error, results) => {
    if (error) {
      res.status(500).json('Error adding broadcaster: ' + error)
      console.error('Error adding broadcaster: ' + error)
    } else {
      res.json({
        message: 'success',
        result: {
          id: results.insertId,
          name: name,
        },
      })
    }
  })
})

/* VPNs */
router.post('/vpns/get', checkAuth, (req, res) => {
  con.query('SELECT * FROM vpns ORDER BY name ASC', (error, results) => {
    if (error) {
      res.status(500).json('Error fetching VPNs: ' + error)
      console.error('Error fetching VPNs: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/vpns/save', checkAuth, (req, res) => {
  const { vpns } = req.body

  // First, clear existing VPNs
  con.query('DELETE FROM vpns', (deleteError) => {
    if (deleteError) {
      res.status(500).json('Error clearing VPNs: ' + deleteError)
      console.error('Error clearing VPNs: ' + deleteError)
      return
    }

    // Then insert new VPNs
    if (vpns && vpns.length > 0) {
      const values = vpns.map((vpn) => {
        if (typeof vpn === 'string') {
          return [vpn, null, null] // name, description, logo_path
        } else {
          return [vpn.name, vpn.description || null, vpn.logo_path || null]
        }
      })
      const query = 'INSERT INTO vpns (name, description, logo_path) VALUES ?'

      con.query(query, [values], (insertError, results) => {
        if (insertError) {
          res.status(500).json('Error saving VPNs: ' + insertError)
          console.error('Error saving VPNs: ' + insertError)
        } else {
          res.json({
            message: 'success',
            result: results,
          })
        }
      })
    } else {
      res.json({
        message: 'success',
        result: { message: 'No VPNs to save' },
      })
    }
  })
})

router.post('/vpns/delete', checkAuth, (req, res) => {
  const { id } = req.body

  con.query('DELETE FROM vpns WHERE id = ?', [id], (error, results) => {
    if (error) {
      res.status(500).json('Error deleting VPN: ' + error)
      console.error('Error deleting VPN: ' + error)
    } else {
      if (results.affectedRows === 0) {
        res.status(404).json({
          message: 'VPN not found',
        })
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  })
})

router.post('/vpns/add', checkAuth, upload.single('logo'), (req, res) => {
  const { name, description } = req.body
  const logoPath = req.file ? req.file.path : null

  con.query(
    'INSERT INTO vpns (name, description, logo_path) VALUES (?, ?, ?)',
    [name, description || null, logoPath],
    (error, results) => {
      if (error) {
        res.status(500).json('Error adding VPN: ' + error)
        console.error('Error adding VPN: ' + error)
      } else {
        res.json({
          message: 'success',
          result: {
            id: results.insertId,
            name: name,
            description: description || null,
            logo_path: logoPath,
          },
        })
      }
    }
  )
})

router.post('/vpns/update', checkAuth, upload.single('logo'), (req, res) => {
  const { vpnId, name, description } = req.body
  const logoPath = req.file ? req.file.path : null

  // First get the current VPN to check if we need to delete the old logo
  con.query('SELECT logo_path FROM vpns WHERE id = ?', [vpnId], (error, results) => {
    if (error) {
      res.status(500).json('Error fetching VPN: ' + error)
      console.error('Error fetching VPN: ' + error)
      return
    }

    if (results.length === 0) {
      res.status(404).json('VPN not found')
      return
    }

    const currentLogoPath = results[0].logo_path

    // If a new logo is uploaded and there's an old logo, delete the old file
    if (logoPath && currentLogoPath) {
      const fs = require('fs')
      if (fs.existsSync(currentLogoPath)) {
        fs.unlinkSync(currentLogoPath)
      }
    }

    // Update the VPN
    const updateQuery = logoPath
      ? 'UPDATE vpns SET name = ?, description = ?, logo_path = ? WHERE id = ?'
      : 'UPDATE vpns SET name = ?, description = ? WHERE id = ?'

    const updateParams = logoPath ? [name, description || null, logoPath, vpnId] : [name, description || null, vpnId]

    con.query(updateQuery, updateParams, (updateError, updateResults) => {
      if (updateError) {
        res.status(500).json('Error updating VPN: ' + updateError)
        console.error('Error updating VPN: ' + updateError)
      } else {
        res.json({
          message: 'success',
          result: {
            id: vpnId,
            name: name,
            description: description || null,
            logo_path: logoPath || currentLogoPath,
          },
        })
      }
    })
  })
})

/* VPN Test Data Storage */
router.post('/vpn-tests/all', checkAuth, (req, res) => {
  const {
    matchday,
    competition,
    broadcaster,
    vpn,
    dateFilter,
    countryChecked,
    countryLocated,
    frenchCardRegistration,
    ligue1ContentWhileActivated,
    testResult,
  } = req.body

  let whereConditions = ['1=1']
  let params = []

  if (matchday) {
    whereConditions.push('matchday = ?')
    params.push(matchday)
  }

  if (competition) {
    whereConditions.push('competition = ?')
    params.push(competition)
  }

  if (broadcaster) {
    whereConditions.push('broadcaster = ?')
    params.push(broadcaster)
  }

  if (vpn) {
    whereConditions.push('vpn = ?')
    params.push(vpn)
  }

  if (dateFilter && dateFilter.startDate && dateFilter.endDate) {
    whereConditions.push('test_date BETWEEN ? AND ?')
    params.push(dateFilter.startDate, dateFilter.endDate)
  }

  if (countryChecked) {
    whereConditions.push('country_checked = ?')
    params.push(countryChecked)
  }

  if (countryLocated) {
    whereConditions.push('country_located = ?')
    params.push(countryLocated)
  }

  if (frenchCardRegistration) {
    whereConditions.push('french_card_registration = ?')
    params.push(frenchCardRegistration)
  }

  if (ligue1ContentWhileActivated) {
    whereConditions.push('ligue1_content_while_activated = ?')
    params.push(ligue1ContentWhileActivated)
  }

  if (testResult) {
    whereConditions.push('test_result = ?')
    params.push(testResult)
  }

  const query = `
    SELECT vt.*, 
           vt.broadcaster as broadcaster_name,
           vt.vpn as vpn_name,
           vt.country_checked,
           vt.country_located,
           vt.french_card_registration,
           vt.vpn_ip_address,
           vt.ligue1_content_while_activated,
           vt.ligue1_content_while_deactivated
    FROM vpn_tests vt
    WHERE ${whereConditions.join(' AND ')}
    ORDER BY vt.test_date DESC
  `

  con.query(query, params, (error, results) => {
    if (error) {
      res.status(500).json('Error fetching VPN tests: ' + error)
      console.error('Error fetching VPN tests: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results,
      })
    }
  })
})

router.post('/vpn-tests/get', checkAuth, (req, res) => {
  con.query(
    `SELECT vt.*, 
            vt.broadcaster as broadcaster_name,
            vt.vpn as vpn_name,
            vt.country_checked,
            vt.country_located,
            vt.french_card_registration,
            vt.vpn_ip_address,
            vt.ligue1_content_while_activated,
            vt.ligue1_content_while_deactivated
     FROM vpn_tests vt
     WHERE vt.id = ?`,
    [req.body.testId],
    (error, results) => {
      if (error) {
        res.status(500).json('Error fetching VPN test: ' + error)
        console.error('Error fetching VPN test: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results[0] || null,
        })
      }
    }
  )
})

router.post('/vpn-tests/add', checkAuth, upload.single('screenshot'), (req, res) => {
  const {
    matchday,
    competition,
    broadcaster,
    vpn,
    testResult,
    notes,
    testDate,
    countryChecked,
    countryLocated,
    frenchCardRegistration,
    vpnIpAddress,
    ligue1ContentWhileActivated,
    ligue1ContentWhileDeactivated,
  } = req.body

  const screenshotPath = req.file ? req.file.path : null

  // Convert string values to integers for tinyint columns
  const convertToTinyint = (value) => {
    if (value === 'yes') return 1
    if (value === 'no') return 0
    return 0 // Default to 0 for empty string, null, or any other value
  }

  con.query(
    `INSERT INTO vpn_tests 
     (matchday, competition, broadcaster, vpn, test_result, notes, screenshot_path, test_date, 
      country_checked, country_located, french_card_registration, vpn_ip_address, ligue1_content_while_activated, ligue1_content_while_deactivated) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      matchday,
      competition,
      broadcaster,
      vpn,
      testResult,
      notes || '',
      screenshotPath,
      testDate || new Date().toISOString().slice(0, 19).replace('T', ' '),
      countryChecked,
      countryLocated,
      convertToTinyint(frenchCardRegistration),
      vpnIpAddress,
      convertToTinyint(ligue1ContentWhileActivated),
      convertToTinyint(ligue1ContentWhileDeactivated),
    ],
    (error, results) => {
      if (error) {
        res.status(500).json('Error adding VPN test: ' + error)
        console.error('Error adding VPN test: ' + error)
      } else {
        res.json({
          message: 'success',
          result: {
            id: results.insertId,
            matchday,
            competition,
            broadcaster,
            vpn,
            testResult,
            notes,
            screenshotPath,
            testDate,
            countryChecked,
            countryLocated,
            frenchCardRegistration,
            vpnIpAddress,
            ligue1ContentWhileActivated,
            ligue1ContentWhileDeactivated,
          },
        })
      }
    }
  )
})

router.post('/vpn-tests/update', checkAuth, upload.single('screenshot'), (req, res) => {
  const {
    testId,
    matchday,
    competition,
    broadcaster,
    vpn,
    testResult,
    notes,
    testDate,
    countryChecked,
    countryLocated,
    frenchCardRegistration,
    vpnIpAddress,
    ligue1ContentWhileActivated,
    ligue1ContentWhileDeactivated,
  } = req.body

  let screenshotPath = null
  let updateFields = []
  let params = []

  // Convert string values to integers for tinyint columns
  const convertToTinyint = (value) => {
    if (value === 'yes') return 1
    if (value === 'no') return 0
    return 0 // Default to 0 for empty string, null, or any other value
  }

  // Build dynamic update query
  if (matchday !== undefined) {
    updateFields.push('matchday = ?')
    params.push(matchday)
  }
  if (competition !== undefined) {
    updateFields.push('competition = ?')
    params.push(competition)
  }
  if (broadcaster !== undefined) {
    updateFields.push('broadcaster = ?')
    params.push(broadcaster)
  }
  if (vpn !== undefined) {
    updateFields.push('vpn = ?')
    params.push(vpn)
  }
  if (testResult !== undefined) {
    updateFields.push('test_result = ?')
    params.push(testResult)
  }
  if (notes !== undefined) {
    updateFields.push('notes = ?')
    params.push(notes)
  }
  if (testDate !== undefined) {
    updateFields.push('test_date = ?')
    params.push(testDate)
  }
  if (countryChecked !== undefined) {
    updateFields.push('country_checked = ?')
    params.push(countryChecked)
  }
  if (countryLocated !== undefined) {
    updateFields.push('country_located = ?')
    params.push(countryLocated)
  }
  if (frenchCardRegistration !== undefined) {
    updateFields.push('french_card_registration = ?')
    params.push(convertToTinyint(frenchCardRegistration))
  }
  if (vpnIpAddress !== undefined) {
    updateFields.push('vpn_ip_address = ?')
    params.push(vpnIpAddress)
  }
  if (ligue1ContentWhileActivated !== undefined) {
    updateFields.push('ligue1_content_while_activated = ?')
    params.push(convertToTinyint(ligue1ContentWhileActivated))
  }
  if (ligue1ContentWhileDeactivated !== undefined) {
    updateFields.push('ligue1_content_while_deactivated = ?')
    params.push(convertToTinyint(ligue1ContentWhileDeactivated))
  }

  // Handle screenshot upload
  if (req.file) {
    screenshotPath = req.file.path
    updateFields.push('screenshot_path = ?')
    params.push(screenshotPath)
  }

  if (updateFields.length === 0) {
    return res.status(400).json('No fields to update')
  }

  params.push(testId)

  const query = `UPDATE vpn_tests SET ${updateFields.join(', ')} WHERE id = ?`

  con.query(query, params, (error, results) => {
    if (error) {
      res.status(500).json('Error updating VPN test: ' + error)
      console.error('Error updating VPN test: ' + error)
    } else {
      if (results.affectedRows === 0) {
        res.status(404).json({
          message: 'VPN test not found',
        })
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    }
  })
})

router.post('/vpn-tests/delete', checkAuth, (req, res) => {
  const { testId } = req.body

  // First get the test to delete the screenshot file if it exists
  con.query('SELECT screenshot_path FROM vpn_tests WHERE id = ?', [testId], (error, results) => {
    if (error) {
      res.status(500).json('Error fetching VPN test: ' + error)
      console.error('Error fetching VPN test: ' + error)
      return
    }

    if (results.length === 0) {
      res.status(404).json({
        message: 'VPN test not found',
      })
      return
    }

    const screenshotPath = results[0].screenshot_path

    // Delete the test record
    con.query('DELETE FROM vpn_tests WHERE id = ?', [testId], (deleteError, deleteResults) => {
      if (deleteError) {
        res.status(500).json('Error deleting VPN test: ' + deleteError)
        console.error('Error deleting VPN test: ' + deleteError)
      } else {
        // Delete the screenshot file if it exists
        if (screenshotPath && fs.existsSync(screenshotPath)) {
          fs.unlink(screenshotPath, (unlinkError) => {
            if (unlinkError) {
              console.error('Error deleting screenshot file:', unlinkError)
            }
          })
        }

        res.json({
          message: 'success',
          result: deleteResults,
        })
      }
    })
  })
})

router.post('/vpn-tests/stats', checkAuth, (req, res) => {
  const {
    matchday,
    competition,
    dateFilter,
    countryChecked,
    countryLocated,
    frenchCardRegistration,
    ligue1ContentWhileActivated,
    testResult,
  } = req.body

  let whereConditions = ['1=1']
  let params = []

  if (matchday) {
    whereConditions.push('matchday = ?')
    params.push(matchday)
  }

  if (competition) {
    whereConditions.push('competition = ?')
    params.push(competition)
  }

  if (dateFilter && dateFilter.startDate && dateFilter.endDate) {
    whereConditions.push('test_date BETWEEN ? AND ?')
    params.push(dateFilter.startDate, dateFilter.endDate)
  }

  if (countryChecked) {
    whereConditions.push('country_checked = ?')
    params.push(countryChecked)
  }

  if (countryLocated) {
    whereConditions.push('country_located = ?')
    params.push(countryLocated)
  }

  if (frenchCardRegistration) {
    whereConditions.push('french_card_registration = ?')
    params.push(frenchCardRegistration)
  }

  if (ligue1ContentWhileActivated) {
    whereConditions.push('ligue1_content_while_activated = ?')
    params.push(ligue1ContentWhileActivated)
  }

  if (testResult) {
    whereConditions.push('test_result = ?')
    params.push(testResult)
  }

  const whereClause = whereConditions.join(' AND ')

  const query = `
    SELECT 
      COUNT(*) as total_tests,
      COUNT(CASE WHEN test_result = 'Success' THEN 1 END) as successful_tests,
      COUNT(CASE WHEN test_result = 'Blocked' THEN 1 END) as blocked_tests,
      COUNT(CASE WHEN test_result = 'Failed' THEN 1 END) as failed_tests,
      COUNT(DISTINCT broadcaster) as unique_broadcasters,
      COUNT(DISTINCT vpn) as unique_vpns,
      COUNT(CASE WHEN french_card_registration = 1 THEN 1 END) as french_card_success,
      COUNT(CASE WHEN ligue1_content_while_activated = 1 THEN 1 END) as ligue1_content_success,
      COUNT(DISTINCT country_checked) as unique_countries_checked,
      COUNT(DISTINCT country_located) as unique_countries_located
    FROM vpn_tests 
    WHERE ${whereClause}
  `

  con.query(query, params, (error, results) => {
    if (error) {
      res.status(500).json('Error fetching VPN test stats: ' + error)
      console.error('Error fetching VPN test stats: ' + error)
    } else {
      res.json({
        message: 'success',
        result: results[0] || {
          total_tests: 0,
          successful_tests: 0,
          blocked_tests: 0,
          failed_tests: 0,
          unique_broadcasters: 0,
          unique_vpns: 0,
        },
      })
    }
  })
})

// Helper endpoint to get distinct values for debugging
router.get('/vpn-reports/distinct-values', checkAuth, (req, res) => {
  // Check if user is a member
  con.query('SELECT type FROM users WHERE token = ?', [req.headers.authorization.split(' ')[1]], (error, results) => {
    if (error || results.length === 0 || results[0].type !== 'Member') {
      return res.status(403).json({ message: 'Access denied. Members only.' })
    }

    // Get distinct matchdays
    con.query(
      'SELECT DISTINCT matchday FROM vpn_tests WHERE matchday IS NOT NULL ORDER BY matchday',
      (error, matchdays) => {
        if (error) {
          return res.status(500).json('Error fetching distinct matchdays: ' + error)
        }

        // Get distinct competitions
        con.query(
          'SELECT DISTINCT competition FROM vpn_tests WHERE competition IS NOT NULL ORDER BY competition',
          (error, competitions) => {
            if (error) {
              return res.status(500).json('Error fetching distinct competitions: ' + error)
            }

            // Get distinct broadcasters
            con.query(
              'SELECT DISTINCT broadcaster FROM vpn_tests WHERE broadcaster IS NOT NULL ORDER BY broadcaster',
              (error, broadcasters) => {
                if (error) {
                  return res.status(500).json('Error fetching distinct broadcasters: ' + error)
                }

                // Get distinct VPNs
                con.query('SELECT DISTINCT vpn FROM vpn_tests WHERE vpn IS NOT NULL ORDER BY vpn', (error, vpns) => {
                  if (error) {
                    return res.status(500).json('Error fetching distinct VPNs: ' + error)
                  }

                  res.json({
                    message: 'success',
                    result: {
                      matchdays: matchdays.map((m) => m.matchday),
                      competitions: competitions.map((c) => c.competition),
                      broadcasters: broadcasters.map((b) => b.broadcaster),
                      vpns: vpns.map((v) => v.vpn),
                    },
                  })
                })
              }
            )
          }
        )
      }
    )
  })
})

/* VPN Reports - Member Only Endpoints */
router.post('/vpn-reports/matchday', checkAuth, (req, res) => {
  // Check if user is a member
  con.query('SELECT type FROM users WHERE token = ?', [req.headers.authorization.split(' ')[1]], (error, results) => {
    if (error || results.length === 0 || results[0].type !== 'Member') {
      return res.status(403).json({ message: 'Access denied. Members only.' })
    }

    const { matchday, competition, broadcaster, vpn } = req.body

    console.log('VPN Matchday Reports - Received filters:', { matchday, competition, broadcaster, vpn })

    let whereConditions = ['1=1']
    let params = []

    if (matchday) {
      whereConditions.push('vt.matchday = ?')
      params.push(matchday)
    }

    // if (competition) {
    //Note: only return data for Ligue 1
    whereConditions.push('vt.competition = ?')
    params.push('Ligue 1')
    // }

    if (broadcaster) {
      whereConditions.push('vt.broadcaster = ?')
      params.push(broadcaster)
    }

    if (vpn) {
      whereConditions.push('vt.vpn = ?')
      params.push(vpn)
    }

    const whereClause = whereConditions.join(' AND ')

    const query = `
      SELECT 
        vt.*,
        vt.broadcaster as broadcaster_name,
        vt.vpn as vpn_name,
        vt.country_checked,
        vt.country_located,
        vt.french_card_registration,
        vt.vpn_ip_address,
        vt.ligue1_content_while_activated,
        vt.ligue1_content_while_deactivated,
        DATE_FORMAT(vt.test_date, '%Y-%m-%d %H:%i') as formatted_date
      FROM vpn_tests vt
      WHERE ${whereClause}
      ORDER BY vt.test_date DESC, vt.matchday ASC
    `

    console.log('VPN Matchday Reports - Query:', query)
    console.log('VPN Matchday Reports - Params:', params)

    con.query(query, params, (error, results) => {
      if (error) {
        res.status(500).json('Error fetching VPN matchday reports: ' + error)
        console.error('Error fetching VPN matchday reports: ' + error)
      } else {
        console.log('VPN Matchday Reports - Results count:', results.length)
        if (results.length > 0) {
          console.log('VPN Matchday Reports - Sample result:', results[0])
        }
        res.json({
          message: 'success',
          result: results,
        })
      }
    })
  })
})

// Weekly VPN Reports with aggregation
router.post('/vpn-reports/weekly', checkAuth, (req, res) => {
  // Check if user is a member
  con.query('SELECT type FROM users WHERE token = ?', [req.headers.authorization.split(' ')[1]], (error, results) => {
    if (error || results.length === 0 || results[0].type !== 'Member') {
      return res.status(403).json({ message: 'Access denied. Members only.' })
    }

    const {
      competition,
      broadcaster,
      vpn,
      dateFilter,
      countryChecked,
      countryLocated,
      frenchCardRegistration,
      ligue1ContentWhileActivated,
      ligue1ContentWhileDeactivated,
      testResult,
    } = req.body

    let whereConditions = ['1=1']
    let params = []

    if (competition) {
      whereConditions.push('vt.competition = ?')
      params.push(competition)
    }

    if (broadcaster) {
      whereConditions.push('vt.broadcaster = ?')
      params.push(broadcaster)
    }

    if (vpn) {
      whereConditions.push('vt.vpn = ?')
      params.push(vpn)
    }

    if (dateFilter && dateFilter.startDate && dateFilter.endDate) {
      whereConditions.push('vt.test_date BETWEEN ? AND ?')
      params.push(dateFilter.startDate, dateFilter.endDate)
    }

    if (countryChecked) {
      whereConditions.push('vt.country_checked = ?')
      params.push(countryChecked)
    }

    if (countryLocated) {
      whereConditions.push('vt.country_located = ?')
      params.push(countryLocated)
    }

    if (frenchCardRegistration) {
      whereConditions.push('vt.french_card_registration = ?')
      params.push(frenchCardRegistration)
    }

    if (ligue1ContentWhileActivated) {
      whereConditions.push('vt.ligue1_content_while_activated = ?')
      params.push(ligue1ContentWhileActivated)
    }

    if (ligue1ContentWhileDeactivated) {
      whereConditions.push('vt.ligue1_content_while_deactivated = ?')
      params.push(ligue1ContentWhileDeactivated)
    }

    if (testResult) {
      whereConditions.push('vt.test_result = ?')
      params.push(testResult)
    }

    const whereClause = whereConditions.join(' AND ')

    const query = `
      SELECT 
        YEARWEEK(vt.test_date, 1) as period,
        vt.broadcaster as broadcaster_name,
        vt.vpn as vpn_name,
        MIN(vt.test_date) as period_start,
        MAX(vt.test_date) as period_end,
        COUNT(*) as total_tests,
        COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) as successful_tests,
        COUNT(CASE WHEN vt.test_result = 'Blocked' THEN 1 END) as blocked_tests,
        COUNT(CASE WHEN vt.test_result = 'Failed' THEN 1 END) as failed_tests,
        ROUND(COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) * 100.0 / COUNT(*), 2) as success_rate
      FROM vpn_tests vt
      WHERE ${whereClause}
      GROUP BY YEARWEEK(vt.test_date, 1), vt.broadcaster, vt.vpn
      ORDER BY period DESC, broadcaster_name ASC, vpn_name ASC
    `

    con.query(query, params, (error, results) => {
      if (error) {
        res.status(500).json('Error fetching VPN weekly reports: ' + error)
        console.error('Error fetching VPN weekly reports: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    })
  })
})

// Monthly VPN Reports with aggregation by broadcaster and VPN
router.post('/vpn-reports/monthly', checkAuth, (req, res) => {
  // Check if user is a member
  con.query('SELECT type FROM users WHERE token = ?', [req.headers.authorization.split(' ')[1]], (error, results) => {
    if (error || results.length === 0 || results[0].type !== 'Member') {
      return res.status(403).json({ message: 'Access denied. Members only.' })
    }

    const {
      competition,
      broadcaster,
      vpn,
      dateFilter,
      countryChecked,
      countryLocated,
      frenchCardRegistration,
      ligue1ContentWhileActivated,
      ligue1ContentWhileDeactivated,
      testResult,
    } = req.body

    let whereConditions = ['1=1']
    let params = []

    if (competition) {
      whereConditions.push('vt.competition = ?')
      params.push(competition)
    }

    if (broadcaster) {
      whereConditions.push('vt.broadcaster = ?')
      params.push(broadcaster)
    }

    if (vpn) {
      whereConditions.push('vt.vpn = ?')
      params.push(vpn)
    }

    if (dateFilter && dateFilter.startDate && dateFilter.endDate) {
      whereConditions.push('vt.test_date BETWEEN ? AND ?')
      params.push(dateFilter.startDate, dateFilter.endDate)
    }

    if (countryChecked) {
      whereConditions.push('vt.country_checked = ?')
      params.push(countryChecked)
    }

    if (countryLocated) {
      whereConditions.push('vt.country_located = ?')
      params.push(countryLocated)
    }

    if (frenchCardRegistration) {
      whereConditions.push('vt.french_card_registration = ?')
      params.push(frenchCardRegistration)
    }

    if (ligue1ContentWhileActivated) {
      whereConditions.push('vt.ligue1_content_while_activated = ?')
      params.push(ligue1ContentWhileActivated)
    }

    if (ligue1ContentWhileDeactivated) {
      whereConditions.push('vt.ligue1_content_while_deactivated = ?')
      params.push(ligue1ContentWhileDeactivated)
    }

    if (testResult) {
      whereConditions.push('vt.test_result = ?')
      params.push(testResult)
    }

    const whereClause = whereConditions.join(' AND ')

    const query = `
      SELECT 
        DATE_FORMAT(vt.test_date, '%Y-%m') as period,
        vt.broadcaster as broadcaster_name,
        vt.vpn as vpn_name,
        MIN(vt.test_date) as period_start,
        MAX(vt.test_date) as period_end,
        COUNT(*) as total_tests,
        COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) as successful_tests,
        COUNT(CASE WHEN vt.test_result = 'Blocked' THEN 1 END) as blocked_tests,
        COUNT(CASE WHEN vt.test_result = 'Failed' THEN 1 END) as failed_tests,
        ROUND(COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) * 100.0 / COUNT(*), 2) as success_rate
      FROM vpn_tests vt
      WHERE ${whereClause}
      GROUP BY DATE_FORMAT(vt.test_date, '%Y-%m'), vt.broadcaster, vt.vpn
      ORDER BY period DESC, broadcaster_name ASC, vpn_name ASC
    `

    con.query(query, params, (error, results) => {
      if (error) {
        res.status(500).json('Error fetching VPN monthly reports: ' + error)
        console.error('Error fetching VPN monthly reports: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    })
  })
})

// Legacy period endpoint for backward compatibility
router.post('/vpn-reports/period', checkAuth, (req, res) => {
  // Check if user is a member
  con.query('SELECT type FROM users WHERE token = ?', [req.headers.authorization.split(' ')[1]], (error, results) => {
    if (error || results.length === 0 || results[0].type !== 'Member') {
      return res.status(403).json({ message: 'Access denied. Members only.' })
    }

    const {
      competition,
      broadcaster,
      vpn,
      dateFilter,
      periodType,
      countryChecked,
      countryLocated,
      frenchCardRegistration,
      ligue1ContentWhileActivated,
      ligue1ContentWhileDeactivated,
      testResult,
    } = req.body

    let whereConditions = ['1=1']
    let params = []

    if (competition) {
      whereConditions.push('vt.competition = ?')
      params.push(competition)
    }

    if (broadcaster) {
      whereConditions.push('vt.broadcaster = ?')
      params.push(broadcaster)
    }

    if (vpn) {
      whereConditions.push('vt.vpn = ?')
      params.push(vpn)
    }

    if (dateFilter && dateFilter.startDate && dateFilter.endDate) {
      whereConditions.push('vt.test_date BETWEEN ? AND ?')
      params.push(dateFilter.startDate, dateFilter.endDate)
    }

    if (countryChecked) {
      whereConditions.push('vt.country_checked = ?')
      params.push(countryChecked)
    }

    if (countryLocated) {
      whereConditions.push('vt.country_located = ?')
      params.push(countryLocated)
    }

    if (frenchCardRegistration) {
      whereConditions.push('vt.french_card_registration = ?')
      params.push(frenchCardRegistration)
    }

    if (ligue1ContentWhileActivated) {
      whereConditions.push('vt.ligue1_content_while_activated = ?')
      params.push(ligue1ContentWhileActivated)
    }

    if (ligue1ContentWhileDeactivated) {
      whereConditions.push('vt.ligue1_content_while_deactivated = ?')
      params.push(ligue1ContentWhileDeactivated)
    }

    if (testResult) {
      whereConditions.push('vt.test_result = ?')
      params.push(testResult)
    }

    const whereClause = whereConditions.join(' AND ')

    let groupBy = ''
    let selectFields = ''

    if (periodType === 'week') {
      selectFields = `
        YEARWEEK(vt.test_date, 1) as period,
        MIN(vt.test_date) as period_start,
        MAX(vt.test_date) as period_end,
        COUNT(*) as total_tests,
        COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) as successful_tests,
        COUNT(CASE WHEN vt.test_result = 'Blocked' THEN 1 END) as blocked_tests,
        COUNT(CASE WHEN vt.test_result = 'Failed' THEN 1 END) as failed_tests
      `
      groupBy = 'GROUP BY YEARWEEK(vt.test_date, 1)'
    } else {
      selectFields = `
        DATE_FORMAT(vt.test_date, '%Y-%m') as period,
        vt.broadcaster as broadcaster_name,
        MIN(vt.test_date) as period_start,
        MAX(vt.test_date) as period_end,
        COUNT(*) as total_tests,
        COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) as successful_tests,
        COUNT(CASE WHEN vt.test_result = 'Blocked' THEN 1 END) as blocked_tests,
        COUNT(CASE WHEN vt.test_result = 'Failed' THEN 1 END) as failed_tests
      `
      groupBy = 'GROUP BY DATE_FORMAT(vt.test_date, "%Y-%m"), vt.broadcaster'
    }

    const query = `
      SELECT 
        ${selectFields}
      FROM vpn_tests vt
      WHERE ${whereClause}
      ${groupBy}
      ORDER BY period DESC
    `

    con.query(query, params, (error, results) => {
      if (error) {
        res.status(500).json('Error fetching VPN period reports: ' + error)
        console.error('Error fetching VPN period reports: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results,
        })
      }
    })
  })
})

router.post('/vpn-reports/summary', checkAuth, (req, res) => {
  // Check if user is a member
  con.query('SELECT type FROM users WHERE token = ?', [req.headers.authorization.split(' ')[1]], (error, results) => {
    if (error || results.length === 0 || results[0].type !== 'Member') {
      return res.status(403).json({ message: 'Access denied. Members only.' })
    }

    const {
      competition,
      broadcaster,
      vpn,
      dateFilter,
      countryChecked,
      countryLocated,
      frenchCardRegistration,
      ligue1ContentWhileActivated,
      ligue1ContentWhileDeactivated,
      testResult,
    } = req.body

    let whereConditions = ['1=1']
    let params = []

    // if (competition) {

    //Note: only return data for Ligue 1
    whereConditions.push('vt.competition = ?')
    params.push('Ligue 1')
    // }

    if (broadcaster) {
      whereConditions.push('vt.broadcaster = ?')
      params.push(broadcaster)
    }

    if (vpn) {
      whereConditions.push('vt.vpn = ?')
      params.push(vpn)
    }

    if (dateFilter && dateFilter.startDate && dateFilter.endDate) {
      whereConditions.push('vt.test_date BETWEEN ? AND ?')
      params.push(dateFilter.startDate, dateFilter.endDate)
    }

    if (countryChecked) {
      whereConditions.push('vt.country_checked = ?')
      params.push(countryChecked)
    }

    if (countryLocated) {
      whereConditions.push('vt.country_located = ?')
      params.push(countryLocated)
    }

    if (frenchCardRegistration) {
      whereConditions.push('vt.french_card_registration = ?')
      params.push(frenchCardRegistration)
    }

    if (ligue1ContentWhileActivated) {
      whereConditions.push('vt.ligue1_content_while_activated = ?')
      params.push(ligue1ContentWhileActivated)
    }

    if (ligue1ContentWhileDeactivated) {
      whereConditions.push('vt.ligue1_content_while_deactivated = ?')
      params.push(ligue1ContentWhileDeactivated)
    }

    if (testResult) {
      whereConditions.push('vt.test_result = ?')
      params.push(testResult)
    }

    const whereClause = whereConditions.join(' AND ')

    const query = `
      SELECT 
        COUNT(*) as total_tests,
        COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) as successful_tests,
        COUNT(CASE WHEN vt.test_result = 'Blocked' THEN 1 END) as blocked_tests,
        COUNT(CASE WHEN vt.test_result = 'Failed' THEN 1 END) as failed_tests,
        COUNT(DISTINCT vt.broadcaster) as unique_broadcasters,
        COUNT(DISTINCT vt.vpn) as unique_vpns,
        COUNT(DISTINCT vt.matchday) as unique_matchdays,
        COUNT(CASE WHEN vt.french_card_registration = 1 THEN 1 END) as french_card_success,
        COUNT(CASE WHEN vt.ligue1_content_while_activated = 1 THEN 1 END) as ligue1_content_success,
        COUNT(DISTINCT vt.country_checked) as unique_countries_checked,
        COUNT(DISTINCT vt.country_located) as unique_countries_located,
        ROUND(COUNT(CASE WHEN vt.test_result = 'Success' THEN 1 END) * 100.0 / COUNT(*), 2) as success_rate
      FROM vpn_tests vt
      WHERE ${whereClause}
    `

    con.query(query, params, (error, results) => {
      if (error) {
        res.status(500).json('Error fetching VPN report summary: ' + error)
        console.error('Error fetching VPN report summary: ' + error)
      } else {
        res.json({
          message: 'success',
          result: results[0] || {
            total_tests: 0,
            successful_tests: 0,
            blocked_tests: 0,
            failed_tests: 0,
            unique_broadcasters: 0,
            unique_vpns: 0,
            unique_matchdays: 0,
            success_rate: 0,
          },
        })
      }
    })
  })
})

// API Endpoint: Get all recognized countries
router.get('/recognized-countries', (req, res) => {
  con.query('SELECT id, name FROM recognized_countries ORDER BY name ASC', (error, results) => {
    if (error) {
      res.status(500).json({ message: 'Database error', error })
    } else {
      res.json(results)
    }
  })
})

app.use('/api', router)

server.listen(port, () => console.log(`Hello world app listening on port ${port}!`))
