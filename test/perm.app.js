/* Copyright (c) 2013-2014 Richard Rodger */
"use strict";




var seneca  = require('seneca')()

var connect = require('connect')

// create a mock user
seneca.use( function (opts){
  seneca.act({role:'web',use:function(req,res,next){
    req.seneca.user = {
      id:'o1',
      perm:{own:[
        {name:'bar',perm$:'r'}
      ]}
    }
    next()
  }})

  return {
    name:'mockuser'
  }
})

seneca.use('..',{
  own:[
    {name:'bar'}
  ]
})


seneca.ready(function(){

  var b1, b2
  seneca.make$('bar',{a:1,owner:'o1'}).save$(function(e,o){b1=o})
  seneca.make$('bar',{a:2,owner:'o2'}).save$(function(e,o){b2=o})

  var barmap = {
    b1:b1,
    b2:b2
  }


  var app = connect()
  app.use(connect.favicon())
  app.use(connect.logger())



  app.use( seneca.service() )

  app.use( function(req,res){
    //console.log(req.seneca)

    var bar = req.seneca.make$('bar')

    var b = barmap[req.url.substring(1)]

    bar.load$(b.id,function(err,data){
      res.writeHead(200)
      res.end(err+' '+data)
    })
  })


  app.listen(3000)

})
