# seneca-perm

### Node.js Seneca permissions module

This module is a plugin for the Seneca framework. It provides a
permissions system for actions. It's also a good example of how you can compose actions by layering plugins onto each other.

This plugin works by wrapping existing actions with a permission checking action. If the permission test passes, the parent
action can proceed. If not, a permission error is generated.

The possible permission checks are:

   * _allow_: simple yes/no
   * _act_: allow only specific actions to pass
   * _entity_: allow only specific actions on entities
   * _own_: allow on specific actions on entities that are 'owned' by given users 

This plugin also understands when it is used in a web server context, and will add a permission specification to 
the req.seneca object if it exists.


### Support

If you're using this module, feel free to contact me on twitter if you
have any questions! :) [@rjrodger](http://twitter.com/rjrodger)

Current Version: 0.1.0

Tested on: node 0.8.16, seneca 0.5.6



### Quick example

```JavaScript
var seneca  = require('seneca')()
seneca.use('echo')


seneca.use( 'perm', {act:[
  {role:'echo'},
]})

seneca.act({role:'perm', cmd:'init'})


seneca.act({role:'echo', foo:'bar', perm$:{allow:true}},function(err,out){
  console.log('foo='+out.foo)
})

seneca.act({role:'echo', foo:'bar', perm$:{allow:false}},function(err,out){
  console.log(err)
})

```

The _perm$_ meta parameter is recognised by this plugin and contains the permission specification to test against.
Normally, you won't set this manually, but generate it using the _role:perm, cmd:makeperm_ action. In a web context, this
plugin also does this for you, based on the perm property of the current user.

Here's an outline of how you would use it in a connect app, using the _user_ and _auth_ plugins to provide user accounts:

```JavaScript
var seneca  = require('seneca')()
var connect = require('connect')

seneca.use('user')
seneca.use('auth')

seneca.use('perm',{
  act:[{role:'echo'}]
})

seneca.use('echo')

seneca.act({role:'perm', cmd:'init'})

var app = connect()
app.use(connect.favicon())
app.use(connect.logger())

app.use( seneca.service() )

app.listen(3000)
```

The perm plugin does not wrap other actions immediately when it is registered. Rather, you call the _role:perm, cmd:init_ action
when you're ready. First you need to add any other plugins and actions that you want to apply permissions checking to.



## Install

```sh
npm install seneca
npm install seneca-perm
```


## Usage

This plugin has two elements. First, the options define the set of actions that permission checks will apply to. Second, permission
checks only occur if there is a _perm$_ metadata argument, containing a permissions specification. 

### Permission options

   * _act_: array of action pins
   * _entity_: array of entity type specifications
   * _own_: array of entity type specifications

These specify the actions to wrap. For example:

```JavaScript
seneca.use( 'perm', {act:[
  {role:'echo'}
]})
```

This wraps any action with a _role:echo_ argument, which means that it will have a permission check applied.

You need to specify explicitly the actions to which you wish to apply permission checks.

As a convenience, you can apply permission checks to entities by simply specifying their zone, base and name:

```JavaScript
seneca.use( 'perm', {entity:[
  {base:'sys'},
  {base:'foo',name:'bar'}
]})
```

The above code specifies that actions on any entity of type -/sys/- or -/foo/bar will have an permission check applied. 

The _entity_ option saves you from having to specify a permission check for all the entity actions:

```JavaScript
seneca.use( 'perm', {act:[
  {role:'entity',cmd:'save',base:'sys'},
  {role:'entity',cmd:'load',base:'sys'},
  {role:'entity',cmd:'list',base:'sys'},
  ...
]})
```

The allowed entity operations (create, read, update, delete, query)
are specified in the perm$ metadata argument to the entity actions
(see below).

The _own_ option works in much the same way as the _entity_ option,
except that the user must be the owner of the entity in question.
Entities should have an _owner_ property containing the identifier of the -/sys/user entity for this to work.

```JavaScript
seneca.use( 'perm', {own:[
  {base:'foo'}
]})
```


### Permission specifications

To trigger a permissions check, an action must contain a perm$ metadata argument. This is an object contains one or more of the
following properties:

   * allow: boolean, true if action is permitted.
   * act: an action router object; only matching actions can be executed
   * entity: an entity type router object, matching the entity action, and specifying the operations permitted
   * own: an entity type router object, matching the entity action, and specifying the operations permitted, if also owner of the entity

You do not normally construct the perm$ object directly, but instead use the _role:perm, cmd:makeperm_ action to create one from a 
literal definition (you can store this in the -/sys/user entity, for example). If you store the definition in a _perm_ property on
-/sys/user, and use the perm plugin in a web context, then this is done for you automatically.


EACH SPEC TYPE


## Test

```bash
cd test
mocha level.test.js --seneca.log.print
```
