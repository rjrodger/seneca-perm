/* Copyright (c) 2013 Richard Rodger, MIT License */
"use strict";


var _       = require('underscore')
var express = require('express')

var seneca = require('seneca')()

// process.on('uncaughtException', function(err) {
//   console.error('uncaughtException:', err.message)
//   console.error(err.stack)
//   process.exit(1)
// })


seneca.use('options','options.mine.js')

seneca.use('mem-store',{web:{dump:true}})

seneca.use('user',{confirm:true})
seneca.use('auth')
seneca.use('../perm.js', {
  entity: true,
  accessControls: [{
    name: 'access to projects',
    roles: ['project_access'],
    entities: [{
      zone: undefined,
      base: undefined,
      name: 'project'
    }],
    control: 'required',
    actions: 'crudq',
    conditions: []
  },{
    name: 'access to secret projects',
    roles: ['secret'],
    entities: [{
      zone: undefined,
      base: undefined,
      name: 'project'
    }],
    control: 'required',
    actions: 'crudq',
    conditions: [{
        attributes: {
          'category': 'secret'
        }
      }
    ]
  }]

})
seneca.use('account')
seneca.use('project')


seneca.ready(function(err){
  if( err ) return process.exit( !console.error(err) );

  var options = seneca.export('options')

  var u = seneca.pin({role:'user',cmd:'*'})
  var projectpin = seneca.pin({role:'project',cmd:'*'})

  u.register({nick:'u1',name:'u1',email:'u1@example.com',password:'1',perm: {roles: ['project_access', 'secret']}, active:true}, function(err,out){
    projectpin.save( {account:out.user.accounts[0], name:'public project', category: 'public'} )
    projectpin.save( {account:out.user.accounts[0], name:'secret project', category: 'secret'} )
  })
  u.register({nick:'u2',name:'u2',email:'u2@example.com',password:'1',perm: {roles: ['project_access']}, active:true}, function(err,out){
    projectpin.save( {account:out.user.accounts[0], name:'public project', category: 'public'} )
    projectpin.save( {account:out.user.accounts[0], name:'secret project that you should not see', category: 'secret'} )
  })
  u.register({nick:'u3',name:'u3',email:'u3@example.com',password:'1',perm: {roles: []}, active:true}, function(err,out){
    projectpin.save( {account:out.user.accounts[0], name:'public project that you should not see', category: 'public'} )
    projectpin.save( {account:out.user.accounts[0], name:'secret project that you should not see', category: 'secret'} )
  })
  u.register({nick:'a1',name:'na1',email:'a1@example.com',password:'a1',active:true,admin:true})

  var web = seneca.export('web')

  var app = express()

  app.use( express.cookieParser() )
  app.use( express.query() )
  app.use( express.bodyParser() )
  app.use( express.methodOverride() )
  app.use( express.json() )

  app.use(express.session({secret:'seneca'}))

  app.use( web )


  app.use( function( req, res, next ){
    if( 0 == req.url.indexOf('/reset') ||
        0 == req.url.indexOf('/confirm') )
    {
      req.url = '/'
    }

    next()
  })


  app.use( express.static(__dirname+options.main.public) )

  app.listen( options.main.port )

  seneca.log.info('listen',options.main.port)

  seneca.listen()

})


