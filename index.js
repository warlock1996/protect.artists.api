require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const nodemailer = require('nodemailer')
const crypto = require('crypto')
const bcrypt = require('bcrypt')
var mysql = require('mysql')
const mysql2 = require('mysql2')

const fs = require('fs')
const path = require('path')
const http = require('http')
const multer = require('multer')

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

app.use('/uploads', express.static('uploads'))

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

app.get('/', (req, res) => {
  res.send('Protect Artists Server')
})

app.get('/api', (req, res) => {
  res.send('Protect Artists Server')
})

router.post('/user/login', async (req, res) => {
  con.query('select * from users where email = ?', [req.body.email], (error, results) => {
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
  })
})

router.post('/user/verifysession', async (req, res) => {
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

router.post('/user/update', (req, res) => {
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

router.post('/user/updatepassword', async (req, res) => {
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
router.post('/members/all', (req, res) => {
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

router.post('/members/get', (req, res) => {
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

router.post('/members/review', (req, res) => {
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

router.post('/members/add', async (req, res) => {
  if (req.body.password.length >= 6) {
    try {
      const userid = crypto.randomBytes(10).toString('hex')
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
router.post('/admins/all', (req, res) => {
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

router.post('/admins/get', (req, res) => {
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

router.post('/admins/add', async (req, res) => {
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

router.post('/admins/update', (req, res) => {
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

router.post('/admins/delete', (req, res) => {
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
router.post('/teams/all', (req, res) => {
  var comp = req.body.comp
  var searchtxt = comp !== '' ? ' and competitions.id = "' + comp + '" ' : ''
  con.query(
    'select teams.*, competitions.name as compname, competitions.logo as complogo from teams LEFT JOIN competitions ON teams.competition = competitions.id where 1 ' +
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

router.post('/teams/get', (req, res) => {
  con.query(
    "SELECT teams.*, competitions.name as compname, competitions.logo as complogo from teams LEFT JOIN competitions ON teams.competition = competitions.id where teams.id = ? and teams.status = 'Active'",
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

router.post('/teams/matches', (req, res) => {
  con.query(
    'SELECT matches.*, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo, competitions.id as competitionId FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and (matches.team1 = ? OR matches.team2 = ?) order by matches.date asc',
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
router.post('/teams/switch', (req, res) => {
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

router.post('/teams/create', upload.single('file'), (req, res) => {
  const players = JSON.parse(req.body.players || JSON.stringify([]))
  con.query(
    'INSERT INTO teams (name, status, competition, logo) VALUES (?,?,?,?)',
    [req.body.name, req.body.status ? 'Active' : 'Inactive', req.body.competition, req.file.path],
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

router.post('/matches/matchdays/all', (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and matches.status = "' + req.body.statusfilter + '" ' : ''
  let comp = req.body.competition
  let response = {
    matchdays: null,
    currentmatchday: null,
    currentmatchdays: null,
  }
  con.query(
    'SELECT DISTINCT(matchday) as matchday from matches where competition = ? order by matchday asc',
    [comp],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        response.matchdays = results
        con.query(
          "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM `matches` LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where matches.competition = ? and matches.matchday = (SELECT matchday FROM `matches` where competition = ? and date >= CURDATE() order by date asc limit 1) order by matches.date asc",
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

router.post('/matches/matchdays/matches', (req, res) => {
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and matchday = ? order by matches.date asc",
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

router.post('/matches/all', (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and matches.status = "' + req.body.statusfilter + '" ' : ''
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 " +
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

router.post('/matches/recent', (req, res) => {
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and matches.date >= CURDATE() order by matches.date asc limit 10",
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

router.post('/matches/get', (req, res) => {
  con.query(
    "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where matches.matchid = ?",
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

router.post('/matches/add', (req, res) => {
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

router.post('/matches/review', (req, res) => {
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

router.post('/matches/update', (req, res) => {
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

router.post('/matches/delete', (req, res) => {
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

router.post('/matches/websites', (req, res) => {
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

router.post('/matches/specwebsites', (req, res) => {
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

router.post('/matches/websites/update', (req, res) => {
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

router.post('/linkcategories/all', (req, res) => {
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

router.post('/linkcategories/get', (req, res) => {
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

router.post('/linkcategories/add', (req, res) => {
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

router.post('/linkcategories/update', (req, res) => {
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

router.post('/linkcategories/delete', (req, res) => {
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

router.post('/linkwebsites/all', (req, res) => {
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

router.post('/linkwebsites/get', (req, res) => {
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

router.post('/linkwebsites/add', (req, res) => {
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

router.post('/linkwebsites/update', (req, res) => {
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

router.post('/linkwebsites/delete', (req, res) => {
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

router.post('/matchdaydata/all', (req, res) => {
  const currentYear = new Date().getFullYear()
  //    var typef = req.body.type !== "" ? ' and matchlinks.type = "' + req.body.type + '" ' : "";
  var competition = req.body.competition
  con.query(
    'SELECT DISTINCT(matches.matchday) AS matchDay, matchdaydata.* FROM matches LEFT JOIN matchdaydata ON matches.matchday = matchdaydata.matchday AND matches.competition = matchdaydata.competition AND matchdaydata.year = ? WHERE matches.competition = ? ORDER BY matches.matchday ASC;',
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

router.post('/matchdaydata/get', (req, res) => {
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

router.post('/matchdaydata/getclosure', (req, res) => {
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

router.post('/matchdaydata/add', (req, res) => {
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

router.post('/matchdaydata/update', (req, res) => {
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

router.post('/matchdaydata/delete', (req, res) => {
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

router.post('/matchlinks/all', async (req, res) => {
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

router.post('/matchlinks/websites', async (req, res) => {
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

router.post('/matchlinks/add', (req, res) => {
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

router.post('/matchlinks/delete', (req, res) => {
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

router.post('/players/all', (req, res) => {
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

router.post('/players/get', (req, res) => {
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

router.post('/players/update', (req, res) => {
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

router.post('/players/switch', (req, res) => {
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

router.post('/players/add', (req, res) => {
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

router.post('/players/delete', (req, res) => {
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

router.post('/score/add', async (req, res) => {
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

router.post('/score/teamscorers', (req, res) => {
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

router.post('/overview/all', (req, res) => {
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

router.post('/overview/stats', (req, res) => {
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

router.post('/overview/domain', async (req, res) => {
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

router.post('/overview/match', (req, res) => {
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

router.post('/reports/matchdays/all', (req, res) => {
  var searchtxt = req.body.statusfilter !== '' ? ' and matches.status = "' + req.body.statusfilter + '" ' : ''
  let comp = req.body.competition
  let response = {
    matchdays: null,
    currentmatchday: null,
    currentmatchdays: null,
  }
  con.query(
    'SELECT DISTINCT(matchday) as matchday from matches where competition = ? order by matchday asc',
    [comp],
    (error, results) => {
      if (error) {
        res.status(500).json('An error occurred: ' + error)
        console.error('An error occurred: ' + error)
      } else {
        response.matchdays = results
        con.query(
          "SELECT matches.*, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM `matches` LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where matches.competition = ? and matches.matchday = (SELECT matchday FROM `matches` where competition = ? and date >= CURDATE() order by date asc limit 1) order by matches.date asc",
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

router.post('/reports/matchdays/matches', (req, res) => {
  con.query(
    "SELECT matches.*, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid) as totallinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid and type = 'Live') as livelinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid and type = 'Highlight') as highlightlinks, (select count(DISTINCT(link)) from matchlinks where matchlinks.matchid = matches.matchid and type = 'Google') as googlelinks, (select SUM(spectators) from matchspectators where matchspectators.matchid = matches.matchid) as totalspectators, DATE_FORMAT(matches.addedat, '%d-%b-%Y') AS addedatdate, t1.name AS team1name, t1.logo AS team1logo, t2.name AS team2name, t2.logo AS team2logo, competitions.name as compname, competitions.logo as complogo FROM matches LEFT JOIN teams AS t1 ON matches.team1 = t1.id LEFT JOIN teams AS t2 ON matches.team2 = t2.id LEFT JOIN competitions ON matches.competition = competitions.id where 1 and matchday = ? and matches.competition = ? order by matches.date asc",
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

router.post('/reports/links/websites', (req, res) => {
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

router.post('/reports/matchday/data', (req, res) => {
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

router.post('/reports/matchday/totals', (req, res) => {
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

router.post('/dashboard/stats', async (req, res) => {
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

      const matchesCount = await queryAsync('SELECT count(*) as count from matches')
      stats.matches = matchesCount[0].count

      const matchestodayCount = await queryAsync('SELECT count(*) as count from matches where date = CURDATE()')
      stats.matchestoday = matchestodayCount[0].count

      const matchestomorrowCount = await queryAsync(
        'SELECT count(*) as count from matches where date = CURDATE() + INTERVAL 1 DAY'
      )
      stats.matchestomorrow = matchestomorrowCount[0].count

      const matchesreviewCount = await queryAsync(
        'SELECT COUNT(*) AS count FROM matches WHERE EXISTS ( SELECT 1 FROM matchlinks WHERE matchlinks.matchid = matches.matchid )'
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

      const matchesCount = await queryAsync('SELECT count(*) as count from matches')
      stats.matches = matchesCount[0].count

      const matchestodayCount = await queryAsync('SELECT count(*) as count from matches where date = CURDATE()')
      stats.matchestoday = matchestodayCount[0].count

      const matchestomorrowCount = await queryAsync(
        'SELECT count(*) as count from matches where date = CURDATE() + INTERVAL 1 DAY'
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
router.post('/competitions/all', (req, res) => {
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
                logo: row.logo,
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

router.post('/competitions/create', upload.single('file'), (req, res) => {
  con.query(
    'INSERT INTO competitions (name, status, logo) VALUES (?,?,?)',
    [req.body.name, req.body.status ? 'Active' : 'Inactive', req.file.path],
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

router.post('/competitions/update', upload.single('file'), (req, res) => {
  const { id, name, status, competitionId } = req.body

  const updateFields = ['name = ?', 'status = ?']
  const updateValues = [name, status]
  if (req.file) {
    updateFields.push('logo = ?')
    updateValues.push(req.file.path)
  }
  updateValues.push(competitionId)

  con.query(`UPDATE competitions SET ${updateFields.join(', ')} WHERE id = ?`, updateValues, (error) => {
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

router.post('/competitions/delete', (req, res) => {
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

app.use('/api', router)

server.listen(port, () => console.log(`Hello world app listening on port ${port}!`))
