const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const sessions = require('client-sessions')
const bcrypt = require('bcryptjs')

let app = express()
app.set('view engine', 'pug')

// MIDDLEWARE
app.use(bodyParser.urlencoded({ extended: false }))
app.use(sessions({
  cookieName: "session",
  secret: "asd09f8ori124hj0asd9j",
  duration: 30 * 60 * 1000   // 30 min
}))

// middleware that check session with db user
app.use((req, res, next) => {

  // check if there's a session available
  if (!(req.session && req.session.userId)) {
    return next()
  } 

  // extract the user id out of the session
  // get the user data back from the database
  User.findById(req.session.userId, (err, user) => {
    if (err) {
      return next(err)
    }
    if (!user) {
      return next()
    }

    // clean the hash password from the user data for security
    // to avoid showing the passaword data on a console.log
    user.password = undefined

    // put the user data into the req object
    req.user = user

    // put the user data into a template accessible object 
    res.locals.user = user

    next()
  })
})

// function to add to secure routes
function loginRequired(req, res, next) {
  if (!req.user) {
    return res.redirect('/login')
  }

  next()
}

// DATABASE
mongoose.connect('mongodb://localhost/auth_node', {useNewUrlParser: true})
let User = mongoose.model("User", new mongoose.Schema({
  firstName:   { type: String, required: true},
  lastName:    { type: String, required: true},
  email:       { type: String, required: true},
  password:    { type: String, required: true}
}))


// ROUTES -------------------------------

app.get('/', (req, res) => {
  res.render('index')
})

app.get('/register', (req, res) => {
  res.render('register')
})

app.post('/register', (req, res) => {
  // hash password
  let hash = bcrypt.hashSync(req.body.password, 14)
  req.body.password = hash


  let user = new User(req.body)

  user.save((err) => {
    if (err) {
      let error = "Something bad happened! Please try again."

      if (err.code === 11000) {
        error = "That email is already taken, please try another."
      }

      return res.render("register", { error: error })
    }
    res.redirect("/dashboard")
  })
})

app.get('/login', (req, res) => {
  res.render('login')
})

app.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    
    console.log(user)
    if (err || !user || !bcrypt.compareSync(req.body.password, user.password)) {
      return res.render('login', { error: 'Incorrect email / password.'})
    }
    
    req.session.userId = user._id
    res.redirect('/dashboard')
  })
})

app.get('/logout', (req, res) => {
  req.session.reset()
  res.redirect('/')
})

app.get('/dashboard', loginRequired, (req, res) => {

  // check if a session is set
  // if (!(req.session && req.session.userId)) {
  //   return res.redirect("/login")
  // }

  // check if the userId in the session is found on the DB
  // User.findById(req.session.userId, (err, user) => {
  //   if (err) {
  //     return next(err)
  //   }

  //   if (!user) {
  //     return res.redirect("/login")
  //   }

  //   // show secure page
  //   res.render('dashboard')
  // })

  res.render('dashboard')
})

// SERVER --------------------------------

app.listen(3000, () => {
  console.log('Server running!')
})
