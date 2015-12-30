/* Copyright (c) 2013-2014 Richard Rodger, MIT License */
"use strict";


var seneca  = require('seneca')()
seneca.use('echo')


seneca.use( '..', {act:[
  {role:'echo'},
]})


seneca.ready(function(){

  seneca.act({role:'echo', foo:'bar', perm$:{allow:true}},function(err,out){
    console.log('foo='+out.foo)
  })

  seneca.act({role:'echo', foo:'bar', perm$:{allow:false}},function(err,out){
    console.log(err)
  })

})
