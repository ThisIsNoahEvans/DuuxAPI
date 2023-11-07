# Duux Fan API
Duux Fan API reverse-engineered & written in Go

Reversed from the iOS app. Tested on a Whisper Flex model.

Only compatible with Duux Fans. Does not support other Duux devices.

_This was written quickly whilst figuring out the API for Duux fans. It is functional, but there are many improvements that **could** be made. I won't be dedicating much time to it._

## Usage

### `login`
**Log into your Duux account.**

This emulates the login procedure of the app. You will be emailed a code to authenticate.

The API tokens are stored in your home folder. They are encrypted using the key defined in `main.go`. _This needs improvement as is not the most secure way of storing tokens._

There is currently no logic to make use of the `refresh_token` provided. Whilst the `access_token` does have an `expires_in` value of over 12 weeks (7776000 seconds), this has not been tested.

#### Usage
`login`

#### Arguments
None.

#### Example
```
$ ./duux login

Logging in...

Enter your email: 
[YOUR_EMAIL]
Successfully sent login code!
Please check your email.

Enter your login code: 
[LOGIN_CODE]
Getting auth token...
Successfully got auth token!
API key saved
API key saved
Getting user...
User data saved to /your/home/folder/.duux-user.json
Successfully got user!
```

### `logout`
**Log out of your Duux account**.

The app does not communicate with the server when logging out - it simply abandons the token. Again, this process is emulated by deleting the access tokens & user data from your home folder.

#### Usage
`logout`

#### Arguments
None.

#### Example
```
$ ./duux logout

Logging out...
Successfully logged out!
```

### `getfans`
**Get all the fans associated with your Duux account.**

This will technically return all Duux devices on your account, not just fans, however this code doesn't explicitly support any other devices - simply because I have none to test with!

You will need the ID shown here for controlling this device specifically.

#### Usage
`getfans`

#### Arguments
None.

#### Example
```
$ ./duux getfans

Getting sensors...

ID      |Type  |Name           |Colour  |Power  |Mode     |Speed  |Vertical  |Horizontal  |Timer    |MAC Address
12345  |20    |DUUX.1.108725  |Black   |On     |Natural  |10     |1         |1           |6 hours  |[DEVICE_MAC]
```

### `getschedule`
**Get all the schedules set for your device.**

#### Usage
`getschedule <fan id>`

#### Arguments
- **Fan ID**: the ID of the fan to control, obtained from `getfans`

#### Example
```
$ ./duux getschedule 12345

Getting schedule...

Schedule(s): 4

Schedule 239724:
- At 06:00:01, only on Monday
- Power: On

Schedule 239725:
- At 07:00, only on Monday
- Power: Off

Schedule 239728:
- At 06:00:01, only on Wednesday
- Power: On
- Mode: Normal
- Speed: 5

Schedule 239729:
- At 08:00, only on Wednesday
- Power: Off
```

### `power`
**Control the power of your fan.**

#### Usage
`power <fan id> <on/off>`

#### Arguments
- **Fan ID**: the ID of the fan to control, obtained from `getfans`
- **Power Action**: the power action to perform, `on` or `off`

#### Example
```
$ ./duux power 12345 on

Setting power...
Successfully set power!
```

### `speed`
**Set the speed of your fan.**

#### Usage
`speed <fan id> <speed, 1-26>`

#### Arguments
- **Fan ID**: the ID of the fan to control, obtained from `getfans`
- **Speed**: the speed to set the fan to, between 1 and 26

#### Example
```
$ ./duux speed 12345 20

Setting speed...
Successfully set speed!
```

### `mode`
**Set the air mode of your fan.**

#### Usage
`mode <fan id> <normal/natural/night>`

#### Arguments
- **Fan ID**: the ID of the fan to control, obtained from `getfans`
- **Air Mode**: the mode to set, either `normal`, `natural`, or `night`

#### Example
```
$ ./duux mode 12345 natural

Setting mode...
Successfully set mode!
```

### `timer`
**Specify how long, from now, until your fan will power off.**

If your fan is not currently powered on, it will be before the timer is started.

#### Usage
`timer <fan id> <hours>`

#### Arguments
- **Fan ID**: the ID of the fan to control, obtained from `getfans`
- **Hours**: how many hours, from now, for the fan to remain on for

#### Example
```
$ ./duux timer 12345 5   

Setting timer...
Setting power...
Successfully set power!
Successfully set timer!
```

### `oscillation`
**Set which ways your fan will oscillate.**

#### Usage
`oscillation <fan id> <vertical/horizontal> <on/off>`

#### Arguments
- **Fan ID**: the ID of the fan to control, obtained from `getfans`
- **Direction**: which direction change, either `vertical` or `horizontal`
- **Action**: what to do with this mode, `on` or `off`

#### Example
```
./duux oscillation 12345 vertical on

Setting oscillation...
Successfully set oscillation!
```