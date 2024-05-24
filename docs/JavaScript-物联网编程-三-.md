# JavaScript 物联网编程（三）

> 原文：[`zh.annas-archive.org/md5/98FAEC66467881BC21EC8531C753D4EC`](https://zh.annas-archive.org/md5/98FAEC66467881BC21EC8531C753D4EC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：用物联网仪表盘构建间谍警察

在本章中，我们将看几个家庭项目。您可以将这些项目与我们在前几章中看到的其他工具结合使用。这样做将有助于提高您的知识，也让您自己开发。本章将涵盖以下主题：

+   检测噪音的间谍麦克风

+   调节交流灯调光器的电流

+   用 RFID 卡控制访问

+   检测烟雾

+   使用树莓派 Zero 构建报警系统

+   从远程仪表盘监控气候

# 检测噪音的间谍麦克风

在本节中，我们将看一个可以在房子里使用的项目，用于检测噪音或声音级别，以便我们可以检测到有人在房子前说话。这个项目包括一个带有麦克风的模块，类似于下面的图像：

![检测噪音的间谍麦克风](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_01.jpg)

## 软件代码

我们需要制作一个程序，可以读取模块发送到 Arduino 板的模拟信号：

```js
const int ledPin =  12;         // the number of the LED pin 
const int thresholdvalue = 400; //The threshold to turn the led on 

void setup() { 
 pinMode(ledPin, OUTPUT); 
 Serial.begin(9600); 
} 

void loop() { 
  int sensorValue = analogRead(A0);   //use A0 to read the electrical signal 
  Serial.print("Noise detected="); 
  Serial.println(sensorValue); 
  delay(100); 
  if(sensorValue > thresholdvalue) 
  digitalWrite(ledPin,HIGH);//if the value read from A0 is larger than 400,then light the LED 
  delay(200); 
  digitalWrite(ledPin,LOW); 
} 

```

然后我们下载草图，在下面的截图中我们有声音级别的结果：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_02.jpg)

在下面的图像中，我们可以看到最终的电路连接到 Arduino 板：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_03.jpg)

# 调节交流灯调光器的电流

在本节中，我们将看到如何调节交流灯。多年来，我一直想解释和分享这样的项目，现在终于可以了。这可以应用于调节家里的灯，以减少家庭用电量：接下来的章节将更详细地解释这个项目。

## 硬件要求

我们需要以下电子元件：

+   H 桥

+   24V 交流变压器

+   两个电阻 22k（1 瓦）

+   一个集成电路（4N25）

+   一个电阻 10k

+   一个 5k 的电位计

+   一个电阻 330 欧姆

+   一个电阻 180 欧姆

+   一个集成电路 MOC3011

+   一个 TRIAC 2N6073

在下面的电路图中，我们可以看到 Arduino 板上调光器的连接：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_04.jpg)

## 软件代码

现在您可以将代码复制到一个名为`Dimner.ino`的文件中，或者只需从此项目的文件夹中获取完整的代码：

```js
int load = 10;  
int intensity = 128; 

void setup() 
{ 
pinMode(loaf, OUTPUT); 
attachInterrupt(0, cross_zero_int, RISING); 
} 

void loop() 
{ 
intensity = map(analogRead(0),0,1023,10,128); 
} 

void cross_zero_int() 
{ 
int dimtime = (65 * intensity);  
delayMicroseconds(dimtime);  
digitalWrite(load, HIGH);  
delayMicroseconds(8);  
digitalWrite(load, LOW); 
} 

```

在下载了草图之后，我们可以看到最终的结果。通过电位器，我们可以调节灯的亮度。在我们的房子里，我们可以随时打开灯：也许我们可以根据环境光控制它们。

在下面的图像中，我们将看到灯的不同时刻，如果我们调节电位器的输入信号：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_05.jpg)

在下面的图像中，我们可以看到调节灯的亮度的结果：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_06.jpg)

在这里我们可以看到灯的调光器处于最大亮度：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_07.jpg)

# 用 RFID 卡控制访问

在本节中，我们将看到如何通过门控制访问。在上一章中，我们看到了如何控制房子的锁和灯。这个项目可以作为上一个项目的补充，因为它可以让您控制门的打开，特定卧室的门，或其他房间的灯。

## 硬件要求

对于这个项目，我们需要以下设备：

+   读取标签卡

+   RFID RC522 模块

+   Arduino 板

下图显示了用于读取和控制访问的 RFID 标签：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_08.jpg)

下图显示了 Arduino 的 RFID 卡接口：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/RFID-RC522-pinout.jpg)

## 软件要求

我们需要安装`<MFRC522.h>`库，这个文件可以与并配置模块以读取标签卡进行通信。这个库可以从[`github.com/miguelbalboa/rfid`](https://github.com/miguelbalboa/rfid)下载。

## 软件代码

现在你可以将代码复制到名为`RFID.ino`的文件中，或者直接从该项目的文件夹中获取完整的代码：

```js
#include <MFRC522.h> 
#include <SPI.h> 
#define SAD 10 
#define RST 5 

MFRC522 nfc(SAD, RST); 

#define ledPinOpen  2 
#define ledPinClose 3 

void setup() { 
  pinMode(ledPinOpen,OUTPUT);    
  pinMode(ledPinClose,OUTPUT); 

  SPI.begin(); 
  Serial.begin(115200); 
  Serial.println("Looking for RC522"); 
  nfc.begin(); 
  byte version = nfc.getFirmwareVersion(); 

  if (! version) { 
    Serial.print("We don't find RC522"); 
    while(1); 
  } 
  Serial.print("Found RC522"); 
  Serial.print("Firmware version 0x"); 
  Serial.print(version, HEX); 
  Serial.println("."); 
} 

#define AUTHORIZED_COUNT 2 //number of cards Authorized 
byte Authorized[AUTHORIZED_COUNT][6] = {{0xC6, 0x95, 0x39, 0x31, 0x5B},{0x2E, 0x7, 0x9A, 0xE5, 0x56}}; 

void printSerial(byte *serial); 
boolean isSame(byte *key, byte *serial); 
boolean isAuthorized(byte *serial); 

void loop() { 
  byte status; 
  byte data[MAX_LEN]; 
  byte serial[5]; 
  boolean Open = false; 
  digitalWrite(ledPinOpen, Open); 
  digitalWrite(ledPinClose, !Open); 
  status = nfc.requestTag(MF1_REQIDL, data); 

  if (status == MI_OK) { 
    status = nfc.antiCollision(data); 
    memcpy(serial, data, 5); 

    if(isAuthorized(serial)) 
    {  
      Serial.println("Access Granted"); 
      Open = true; 
    } 
    else 
    {  
      printSerial(serial); 
      Serial.println("NO Access"); 
      Open = false; 
    } 

    nfc.haltTag(); 
    digitalWrite(ledPinOpen, Open); 
    digitalWrite(ledPinClose, !Open); 
    delay(2000); 

  } 
  delay(500); 
} 

boolean isSame(byte *key, byte *serial) 
{ 
    for (int i = 0; i < 4; i++) { 
      if (key[i] != serial[i]) 
      {  
        return false;  
      } 
    } 
    return true; 
} 

boolean isAuthorized(byte *serial) 
{ 
    for(int i = 0; i<AUTHORIZED_COUNT; i++) 
    { 
      if(isSame(serial, Authorized[i])) 
        return true; 
    } 
   return false; 
} 
void printSerial(byte *serial) 
{ 
    Serial.print("Serial:"); 
    for (int i = 0; i < 5; i++) { 
    Serial.print(serial[i], HEX); 
    Serial.print(" "); 
    } 
} 

```

当我们将标签卡放在连接到 Arduino 的 RFID 模块前时，如果以下代码，它将显示消息（访问已授权）。

在代码的这一部分，我们配置了授权卡的数量：

```js
**#define AUTHORIZED_COUNT 2**
**byte Authorized[AUTHORIZED_COUNT][6] = {{0xC6, 0x95, 0x39, 0x31, 0x5B},
      {0x2E, 0x7, 0x9A, 0xE5, 0x56}};**

```

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_10.jpg)

如果我们将卡片放在未注册的标签和卡上，它可以提供正确的访问：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_11.jpg)

完整连接的最终结果如下图所示：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_12.jpg)

# 检测烟雾

在这一部分，我们将测试一个可以检测烟雾的**MQ135**传感器。这也可以用于家庭检测气体泄漏。在这种情况下，我们将用它来检测烟雾。

在家庭自动化系统中，将所有传感器放置在家中以检测某些东西，我们测量真实世界：在这种情况下，我们使用了可以检测气体和烟雾的 MQ135 传感器，如下图所示：

![检测烟雾](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_13.jpg)

## 软件代码

在下面的代码中，我们解释了如何使用气体传感器编程和检测烟雾：

```js
const int sensorPin= 0; 
const int buzzerPin= 12; 
int smoke_level; 

void setup() { 
Serial.begin(115200);  
pinMode(sensorPin, INPUT); 
pinMode(buzzerPin, OUTPUT); 
} 

void loop() { 
smoke_level= analogRead(sensorPin); 
Serial.println(smoke_level); 

if(smoke_level > 200){  
digitalWrite(buzzerPin, HIGH); 
} 

else{ 
digitalWrite(buzzerPin, LOW); 
} 
} 

```

如果它没有检测到烟雾，它会产生以下数值，如下截图所示：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_14.jpg)

如果检测到烟雾，测量值在*305*和*320*之间，可以在文件中看到如下截图：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_15.jpg)

完整电路连接的最终结果如下图所示：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_16.jpg)

# 使用树莓派 Zero 构建警报系统

在这一部分，我们将使用一个 PIR 传感器连接到树莓派 Zero 来构建一个简单的警报系统。这是一个重要的项目，因为它可以添加到家庭中，包括其他传感器，以便监控。

## 使用树莓派 Zero 的运动传感器

对于这个项目，我们需要树莓派 Zero、一个运动传感器 PIR 和一些电缆。实际上，这个项目的硬件配置将非常简单。首先，将运动传感器的**VCC**引脚连接到树莓派上的一个**3.3V**引脚。然后，将传感器的**GND**引脚连接到树莓派上的一个**GND**引脚。最后，将运动传感器的**OUT**引脚连接到树莓派上的**GPIO17**引脚。你可以参考前面的章节了解树莓派 Zero 板上的引脚映射。

以下图片显示了连接的最终电路：

![使用树莓派 Zero 的运动传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_17.jpg)

## 软件代码

现在你可以将代码复制到名为`Project1`的文件夹中，或者直接从该项目的文件夹中获取完整的代码：

```js
// Modules 
var express = require('express'); 

// Express app 
var app = express(); 

// aREST 
var piREST = require('pi-arest')(app); 
piREST.set_id('34f5eQ'); 
piREST.set_name('motion_sensor'); 
piREST.set_mode('bcm'); 

// Start server 
app.listen(3000, function () { 
  console.log('Raspberry Pi Zero motion sensor started!'); 
}); 

```

## 警报模块

通常，家中会有模块，在检测到运动时会闪烁灯光并发出声音。当然，你也可以将其连接到真正的警报器而不是蜂鸣器，以便在检测到任何运动时发出响亮的声音。

要组装这个模块，首先将 LED 与 330 欧姆电阻串联放在面包板上，LED 的最长引脚与电阻接触。还要将蜂鸣器放在面包板上。然后，将电阻的另一端连接到树莓派上的**GPIO14**，LED 的另一端连接到树莓派上的一个**GND**引脚。对于蜂鸣器，将标有**+**的引脚连接到**GPIO15**，另一端连接到树莓派上的一个**GND**引脚。

## 软件代码

下面是编码细节：

```js
// Modules 
var express = require('express'); 

// Express app 
var app = express(); 

// aREST 
var piREST = require('pi-arest')(app); 
piREST.set_id('35f5fc'); 
piREST.set_name('alarm'); 
piREST.set_mode('bcm'); 

// Start server 
app.listen(3000, function () { 
  console.log('Raspberry Pi Zero alarm started!'); 
}); 

```

这是显示连接的最终电路：

![软件代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_18.jpg)

## 中央接口

首先，我们使用以下代码为应用程序创建一个中央接口：

```js
// Modules 
var express = require('express'); 
var app = express(); 
var request = require('request'); 

// Use public directory 
app.use(express.static('public')); 

// Pi addresses 
var motionSensorPi = "192.168.1.104:3000"; 
var alarmPi = "192.168.1.103:3000" 

// Pins 
var buzzerPin = 15; 
var ledPin = 14; 
var motionSensorPin = 17; 

// Routes 
app.get('/', function (req, res) { 
res.sendfile(__dirname + '/public/interface.html'); 
}); 

app.get('/alarm', function (req, res) { 
  res.json({alarm: alarm}); 
}); 

app.get('/off', function (req, res) { 

  // Set alarm off 
  alarm = false; 

  // Set LED & buzzer off 
  request("http://" + alarmPi + "/digital/" + ledPin + '/0'); 
  request("http://" + alarmPi + "/digital/" + buzzerPin + '/0'); 

  // Answer 
  res.json({message: "Alarm off"}); 

}); 

// Start server 
var server = app.listen(3000, function() { 
    console.log('Listening on port %d', server.address().port); 
}); 

// Motion sensor measurement loop 
setInterval(function() { 

  // Get data from motion sensor 
  request("http://" + motionSensorPi + "/digital/" + motionSensorPin, 
    function (error, response, body) { 

      if (!error && body.return_value == 1) { 

        // Activate alarm 
        alarm = true; 

        // Set LED on 
        request("http://" + alarmPi + "/digital/" + ledPin + '/1'); 

        // Set buzzer on 
        request("http://" + alarmPi + "/digital/" + buzzerPin + '/1'); 

      } 
  }); 

}, 2000);
```

## 图形界面

现在让我们看看界面文件，从 HTML 开始。我们首先导入项目所需的所有库和文件。

```js
<!DOCTYPE html> 
<html> 

<head> 
  <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script> 
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css"> 
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script> 
  <script src="js/script.js"></script> 
  <link rel="stylesheet" href="css/style.css"> 
  <meta name="viewport" content="width=device-width, initial-scale=1"> 
</head> 

<script type="text/javascript"> 

/* Copyright (C) 2007 Richard Atterer, richardÂ©atterer.net 
   This program is free software; you can redistribute it and/or modify it 
   under the terms of the GNU General Public License, version 2\. See the file 
   COPYING for details. */ 

var imageNr = 0; // Serial number of current image 
var finished = new Array(); // References to img objects which have finished downloading 
var paused = false; 

</script> 
<div id="container"> 

  <h3>Security System</h3> 
  <div class='row voffset50'> 
  <div class='col-md-4'></div> 
  <div class='col-md-4 text-center'> 
      Alarm is OFF 
    </div> 
    <div class='col-md-4'></div> 

  </div> 

  <div class='row'> 

    <div class='col-md-4'></div> 
    <div class='col-md-4'> 
      <button id='off' class='btn btn-block btn-danger'>Deactivate Alarm</button> 
    </div> 
    <div class='col-md-4'></div> 

  </div> 

  </div> 

</body> 
</html> 

```

# 从远程仪表板监控气候

如今，大多数智能家居都连接到互联网，这使用户能够监控他们的家。在本节中，我们将学习如何远程监控您的气候。首先，我们只需向树莓派 Zero 添加一个传感器，并从云仪表板监测测量值。让我们看看它是如何工作的。

以下图片显示了最终的连接：

![从远程仪表板监控气候](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_19.jpg)

## 探索传感器测试

```js
var sensorLib = require('node-dht-sensor'); 
var sensor = { 
    initialize: function () { 
        return sensorLib.initialize(11, 4); 
    }, 
    read: function () { 
        var readout = sensorLib.read(); 
        console.log('Temperature: ' + readout.temperature.toFixed(2) + 'C, ' + 
            'humidity: ' + readout.humidity.toFixed(2) + '%'); 
        setTimeout(function () { 
            sensor.read(); 
        }, 2000); 
    } 
}; 

if (sensor.initialize()) { 
    sensor.read(); 
} else { 
    console.warn('Failed to initialize sensor'); 
} 

```

## 配置远程仪表板（Dweet.io）

我们需要访问[`freeboard.io`](http://freeboard.io)并创建一个账户：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_20.jpg)

现在，我们创建一个新的仪表板来控制传感器：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_21.jpg)

使用以下参数添加新的数据源：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_22.jpg)

在仪表板内创建一个新的窗格，并为温度创建一个**表盘**小部件：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_23.jpg)

然后我们会立即在界面上看到温度：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_24.jpg)

我们也可以用湿度做同样的操作：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_25.jpg)

我们应该看到最终结果：

![配置远程仪表板（Dweet.io）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_07_26.jpg)

# 总结

在本章中，我们学习了如何构建和集成基于树莓派 Zero 和 Arduino 板的模块化安全系统。当然，有许多方法可以改进这个项目。例如，您可以简单地向项目添加更多模块，比如更多触发相同警报的运动传感器。即使您不在家庭 Wi-Fi 网络之外，也可以监控系统。

在下一章中，我们将学习如何从 Android 应用程序控制您的系统，以及如何从智能手机集成一个真实的系统，这太棒了！


# 第八章：从智能手机监控和控制您的设备

在之前的章节中，我们已经看到了从 Web 界面控制的项目。现在在本章中，我们将看到如何从 Android 的本机应用程序中控制您的 Arduino 和树莓派，使用平台来创建应用程序以进行控制和监视。

在本章中，我们将看到使用 Android 工具的不同项目和应用程序，将涵盖的主题如下：

+   使用 APP Inventor 从智能手机控制继电器

+   在 Android Studio 中读取 JSON 响应使用以太网盾

+   从 Android 应用程序控制直流电机

+   使用您的树莓派 Zero 从 Android 控制输出

+   通过蓝牙使用树莓派控制输出

# 使用 APP Inventor 从智能手机控制继电器

在本节中，我们将看到如何使用**APP Inventor**创建一个 Android 应用程序来控制连接到 Arduino 板的继电器。

## 硬件要求

项目所需的硬件如下：

+   继电器模块

+   Arduino UNO 板

+   以太网盾

+   一些电缆

## 软件要求

项目所需的软件如下：

+   软件 Arduino IDE

+   您需要激活 Gmail 帐户

# 创建我们的第一个应用程序

App Inventor for Android 是由 Google 最初提供的开源网络应用程序，现在由麻省理工学院（MIT）维护。它允许初学者为 Android 操作系统（OS）创建软件应用程序。它使用图形界面，非常类似于 Scratch 和 StarLogo TNG 用户界面，允许用户拖放可视对象以创建可以在 Android 设备上运行的应用程序。在创建 App Inventor 时，Google 利用了在教育计算领域的重要先前研究，以及 Google 在在线开发环境方面的工作。

您无需在计算机上安装任何软件来执行 APP Inventor；您只需要您的 Gmail 帐户来访问 APP Inventor 界面。

要进入 APP Inventor，只需访问：[`appinventor.mit.edu/explore/`](http://appinventor.mit.edu/explore/)。

转到创建应用程序开始设计应用程序。

首先，我们需要一个 Gmail 帐户；我们需要创建如下图所示的文件：

![创建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_01.jpg)

转到菜单**项目**和**开始新项目**：

![创建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_02.jpg)

写下项目的名称：

![创建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_03.jpg)

在下图中，我们将项目的名称写为**aREST**：

![创建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_04.jpg)

按下**确定**，我们将看到项目已创建：

![创建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_05.jpg)

## 设计界面

现在是时候看看如何创建应用程序的界面了，创建项目后，我们点击项目名称，然后会看到以下屏幕：

![设计界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_06.jpg)

在左侧的用户界面中（您可以看到所有对象），要将对象移动到主屏幕，只需拖动**Web Viewer**和**Button**，如下图所示：

![设计界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_07.jpg)

在上一张屏幕截图中，我们可以看到我们将用来控制 Arduino 板的应用程序界面。

## 使用 APP Inventor 与 Arduino 以太网盾通信

现在我们将看到如何通过以太网网络与 Arduino 通信应用程序。

在**Web Viewer**控件的属性中，我们将看到主页 URL：

![使用 APP Inventor 与 Arduino 以太网盾通信](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_08a.jpg)

在这两个控件中，我们有我们的 Arduino 以太网盾的 URL，我们将使用`RESTful`服务发出请求，并将从应用程序发送以下请求：

+   `http://192.168.1.110/digital/7/1`

+   `http://192.168.1.110/digital/7/0`

## APP Inventor 的代码

原始版本的块编辑器在单独的 Java 进程中运行，使用`Open Blocks Java`库创建可视块编程语言和编程。

当我们点击按钮时，我们有 APP 发明者的代码，为了做到这一点，你只需要做以下事情：

+   转到显示**块**的屏幕界面

+   每个按钮拖动`当...执行`模块

+   在刚刚拖动的模块内部，放置`Call...WebViewer.GoToUrl`模块

+   在模块的 URL 中，放置`WebViewer.HomeUrl`模块

关闭应用程序：

+   拖动`当...按钮点击时执行`模块

+   并在模块内部放置关闭应用程序模块

![APP Inventor 的代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_09.jpg)

当我们打开 Web 浏览器时，我们将得到以下结果：

![APP Inventor 的代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_10.jpg)

以下截图显示了应用程序在手机上运行的情况：

![APP Inventor 的代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_11.jpg)

以下图像显示了连接的最终结果：

![APP Inventor 的代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_12.jpg)

# 使用以太网盾在 Android Studio 中读取 JSON 响应

在本节中，我们将看到如何从 Arduino 板读取响应并在 Android Studio 中读取。

在我们继续下一部分之前，我们需要做以下事情：

+   安装 Android Studio 的 IDE，可以从以下网址获取：[`developer.android.com/studio/index.html?hl=es-419`](https://developer.android.com/studio/index.html?hl=es-419)

+   获取 Android Studio 的最新 SDK

然后我们将在 Android Studio 中创建一个项目，如下截图所示：

![使用以太网盾在 Android Studio 中读取 JSON 响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_13.jpg)

然后选择我们想要使用的 API 版本并单击**下一步**按钮：

![使用以太网盾在 Android Studio 中读取 JSON 响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_14.jpg)

然后选择**空白活动**并单击**下一步**按钮：

![使用以太网盾在 Android Studio 中读取 JSON 响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_15.jpg)

输入您的 Activity 和 Layout 的名称，然后单击**完成**按钮：

![使用以太网盾在 Android Studio 中读取 JSON 响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_16.jpg)

# Android 应用程序

在本节中，我们将看到 Android 应用程序。在您的文件夹中，打开关于 Android Studio 的项目文件。

这里是界面代码生成的 XML 代码：

```js
FrameLayout  

    android:id="@+id/container" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    tools:context=".MainActivity"> 
    tools:ignore="MergeRootFrame"> 

    <WebView 
        android:id="@+id/activity_main_webview" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" /> 
</FrameLayout> 

```

## Java 类

当我们创建项目时，一些类会自动生成，我们将在以下行中看到：

1.  类的名称：

```js
        import android.webkit.WebView; 

```

1.  主类：

```js
        public class MonitoringTemperatureHumidity extends
          ActionBarActivity { 

            private WebView mWebView; 

```

在 Android 应用程序的这一部分中，我们请求值：

```js
mWebView.loadUrl("http://192.168.1.110/temperature");
mWebView.loadUrl("http://192.168.1.110/humidity");
super.onCreate(savedInstanceState);
setContentView(R.layout.activity_monitoring_temperature_humidity);
```

我们定义将包含在主活动中的对象，在这种情况下是`mWebView`控件，它在应用程序的主活动中定义：

```js
    mWebView = (WebView)  findViewById(R.id.activity_main_webview);
    mWebView.loadUrl("http://192.168.1.110/humidity");
}
```

## 应用程序的权限

为了给予应用程序执行网络权限的权限，我们需要在 Android 清单文件中添加以下行：

```js
<uses-permission android:name="android.permission.INTERNET"/>
```

当应用程序在设备上调试和安装后，我们将在屏幕上看到以下结果，显示`温度`的值：

![应用程序的权限](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_17.jpg)

`湿度`的值：

![应用程序的权限](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_18.jpg)

# 使用 Android 应用程序控制直流电机

在本节中，我们将有一个应用程序来将我们的智能手机与手机的蓝牙连接起来，它被称为**Amarino**，你可以从以下网址获取：[`www.amarino-toolkit.net/index.php/home.html`](http://www.amarino-toolkit.net/index.php/home.html)。我们还将看到如何从 Android 应用程序控制直流电机，让我们深入研究一下！

## 硬件要求

在下图中，我们看到以下电路（L293D）用于控制电机的速度和转向：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_19.jpg)

在下图中，我们有电路连接到 Arduino 板的最终连接：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_20.jpg)

最终界面显示在以下截图中：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_21.jpg)

最终结果显示在以下图像中，带有连接：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_22.jpg)

# 使用 Raspberry Pi Zero 从 Android 控制输出

在本节中，我们将看到如何使用在`Node.js`服务器中运行的`control.js`脚本来控制连接到 Raspberry Pi 的输出。

我们需要使用 Android 应用程序控制 LED 输出的请求如下：

1.  `http://192.168.1.111:8099/ledon`

1.  `http://192.168.1.111:8099/ledoff`![使用 Raspberry Pi Zero 从 Android 控制输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_23.jpg)

在 APP Inventor 中创建的界面将类似于以下截图：

![使用 Raspberry Pi Zero 从 Android 控制输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_24.jpg)

最终电路连接将如以下截图所示：

![使用 Raspberry Pi Zero 从 Android 控制输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_25.jpg)

# 通过蓝牙使用 Raspberry Pi 控制输出

一旦您尝试与使用蓝牙模块连接到 Raspberry Pi 的串行端口的其他电子设备进行通信，情况就会有所不同。

这些模块非常便宜，实际模块是坐落在我的模型的插板上的绿色板。纯 HC-05 只能在*3.3V*电平上工作，而不能在*5V-TTL*电平上工作。因此，人们需要电平转换器（再次）。

在本节中，我们将 Raspberry Pi Zero 与蓝牙模块进行通信，并连接 Raspberry Pi 的**TX**和**RX**引脚。

首先，我们需要配置系统文件，进行一些更改以激活 Raspberry Pi Zero TX 和 RX 的通信：

![通过蓝牙使用 Raspberry Pi 控制输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_26.jpg)

## 从 Android 应用程序控制灯光

我们需要下载蓝牙终端，如下截图所示：

![从 Android 应用程序控制灯光](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_27.jpg)

以下截图显示了发送数字 1、2、3、4、5 和 6 的结果：

![从 Android 应用程序控制灯光](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_28.jpg)

以下图像显示了项目的最终部分以及与 HC05 模块和 Raspberry Pi Zero 的连接：

![从 Android 应用程序控制灯光](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_08_29.jpg)

# 总结

在本章中，您学会了如何使用 Android Studio 和 APP inventor 通过蓝牙和以太网通信从智能手机控制 Arduino 和 Raspberry Pi Zero。我们还研究了几个项目，如控制电机、控制继电器模块以及读取湿度和温度。对于未来的项目，您现在可以在应用程序的任何区域控制和监视任何您想要的东西。

在下一章中，我们将整合前几章的所有内容，并将所有知识应用到一起。


# 第九章：将所有内容放在一起

之前的章节为我们提供了设计和组装整个家庭系统的基础和元素，我们将在本章中进行研究。我希望我已经以相当结构化和逻辑的方式引导您进行了这次旅程，以便您已经准备好了。

作为构建整个系统的指南，在本章中，我们将指导您如何整合并给出一些将所有内容放在一起的想法，并为您提供最终的细节。然后，您可以使用我们在本章中提到的想法制作自己的项目。

在本章中，我们将涵盖以下主题：

+   整合系统-开发项目

+   使用矩阵键盘控制访问

+   将系统控制与继电器和设备集成

+   如何设置电源供应

# 整合系统-开发项目

在之前的章节中，我们已经看到了关于家庭自动化和家用电器控制和监控的不同项目。在本章中，我们将提供一些想法，开发一些可以在不同领域使用电子设备进行控制和监控的项目。

## 深入了解光传感器

正如其名称所示，“光敏电阻（LDR）”由一块暴露的半导体材料制成，例如硫化镉，当光照射到它时，它的电阻从黑暗中的几千欧姆变为只有几百欧姆，通过在材料中创建空穴-电子对。净效应是其导电性的改善，随着照明的增加，电阻减小。此外，光敏电池具有长时间的响应，需要多秒钟才能对光强度的变化做出反应。

在本节中，我们将看看如何使用光传感器来控制不同的设备：

+   需要时开关灯光

+   当传感器检测到房间内是否有光线时，调暗灯光

![深入了解光传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_01.jpg)

可以使用信号传感器调暗灯光；根据光传感器测量的数据，可以调节其强度。

![深入了解光传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_02.jpg)

## 运动传感器

运动传感器检测体热（红外能量）。被动红外传感器是家庭安全系统中最广泛使用的运动传感器。当您的系统处于武装状态时，您的运动传感器会被激活。一旦传感器变热，它就可以检测周围区域的热量和运动，形成一个保护网格。

如果移动物体阻挡了太多的网格区域，并且红外能量级别迅速变化，传感器就会触发。使用这个传感器，我们可以在需要时控制灯光的开关：

![运动传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_03.jpg)

根据传感器测量的距离，它可以检测物体，因此您可以控制灯光：

![运动传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_04.jpg)

## 自动光控制器

当您不在家时，或者当您告诉系统您不在家时，传感器会起作用。一些安全系统可以被编程，当检测到运动时通过安全摄像头记录事件。运动检测的主要目的是感应入侵者并向您的控制面板发送警报，从而向您的监控中心发出警报：

![自动光控制器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_05.jpg)

以下电路图显示了自动光控制的连接，其中使用了之前使用的所有元素，如 LDR 传感器、PIR 传感器和继电器模块：

![自动光控制器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_06.jpg)

# 太阳能电源监控电路

这里有另一个真实项目，显示了一个控制面板，将使用 Arduino 板监控太阳能电池板的能量。以下图表显示了传感器和太阳能电池板连接到 Arduino 板的连接：

![太阳能电源监控电路](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_07.jpg)

# 带土壤传感器的自动灌溉系统

在下图中，我们有另一个项目；我们正在整合以前使用过的工具。在这种情况下，我们将使用土壤传感器在有或无水时控制浇水：

![带土壤传感器的自动灌溉系统](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_08.jpg)

到目前为止，您已经看到了可以应用于真实情况的非常有趣和有价值的项目，涉及不同领域，如家庭、家庭自动化，甚至花园。在接下来的章节中，我们将看更多的项目。让我们开始吧！

# Arduino 水位控制器

在这个项目中，我们将制作一个自动水位传感器，使用您的 Arduino 板来控制水位，如下图所示：

![Arduino 水位控制器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_09.jpg)

# 基于蓝牙的家庭自动化

在本节中，我们将看一个可以用于家庭自动化的项目，使用蓝牙模块进行通信，继电器模块和硬件集成作为软件工具来控制房屋中的设备。

下图显示了如何将继电器模块和 HC05 蓝牙模块连接到 Arduino 板：

![基于蓝牙的家庭自动化](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_10.jpg)

# 使用矩阵键盘控制访问

在本节中，我们将看如何使用矩阵键盘控制访问代码。在下图中，我们可以看到我们将使用的键盘：

![使用矩阵键盘控制访问](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_11.jpg)

## 键盘

在下图中，我们看到了与 Arduino 板的硬件连接。它们连接到数字引脚：

![键盘](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_12.jpg)

## 连接 LCD 屏幕显示代码

在下图中，我们展示了 LCD 屏幕与 Arduino 板的硬件连接：

![连接 LCD 屏幕显示代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_13.jpg)

我们已经看过一些有趣的项目，您可以通过添加新的传感器来控制其他设备。在下一节中，我们将看一个非常有趣的项目。准备好迈出下一步，这是一个很好的目标。

# 使用键盘控制门锁

在下图中，我们看到了一个带锁的键盘。这一部分可以与上一个项目合并。这个设备可以从您的 Raspberry Pi Zero 或 Arduino 板上进行控制：

![使用键盘控制门锁](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_14.jpg)

## 使用键盘访问的代码

您现在可以将代码复制到名为 Project_keyboard_Access_Control.ino 的文件中，或者只需使用 Arduino IDE 从此项目的文件夹中获取完整的代码：

```js
void captura() 
{ 
  tecla = customKeypad.getKey(); 

  if (tecla) 
  { 
    digito = digito + 1; 
    if(tecla==35){tecla=0;digito=0;valorf=0;lcd.setCursor(0,0);lcd.print(valorf);
      lcd.print("          ");}          
    if(tecla==48){tecla=0;} 
    if(tecla==42){tecla=0;digito=0;valor = valorf;} 

   if(digito==1){valorf1 = tecla; valorf=valorf1;lcd.setCursor(0,0);
       lcd.print(valorf);lcd.print("          ");}  
     if(digito==2){valorf2 = tecla+(valorf1*10);valorf=valorf2;lcd.setCursor(0,0);
         lcd.print(valorf);lcd.print("          ");} 
    if(digito==3){valorf3 = tecla+(valorf2*10);valorf=valorf3;lcd.setCursor(0,0);
         lcd.print(valorf);lcd.print("          ");} 
    if(digito==4){valorf4 = tecla+(valorf3*10);valorf=valorf4;lcd.setCursor(0,0);
         lcd.print(valorf);lcd.print("          ");} 
    if(digito==5){valorf5 = tecla+(valorf4*10);valorf=valorf5;lcd.setCursor(0,0);
        lcd.print(valorf);lcd.print("          ");digito=0;} 
  } 

```

此功能检查键入的代码是否正确：

```js
void loop() 
{ 
  captura(); 
  if (valor == 92828) 
  { 
    digitalWrite(lock,HIGH); 
  } 
  if (valor == 98372) 
  { 
    digitalWrite(lock,LOW); 
  } 
} 

```

# 集成系统控制与继电器和设备

在下图中，我们正在整合书中的重要部分。我们将展示使用继电器在房屋中的连接，以及如何应用和控制真实负载使用灯：

![集成系统控制与继电器和设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_15.jpg)

## 控制多个电器

在现实生活中，我们将看到连接并控制真实世界的设备。在下图中，我们可以看到可以控制电子部分负载的继电器模块：

![控制多个电器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_16.jpg)

下图显示了最终电路。我们看到了与 Arduino 板的真实连接，以及它们如何控制真实世界。

![控制多个电器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_17.jpg)

## 完整系统

在下图中，我们看到了控制家庭自动化系统中真实设备的最终电路。这可以在家中的所有区域使用，在每个房间中我们可以有一个继电器模块，与控制系统通信：

![完整系统](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_18.jpg)

# 如何设置电源供应

对于我们的系统，设置系统中将使用的电源非常重要。首先，我们需要确保 Arduino 的电压约为 5V。在下图中，我们展示了如何将电压配置为约 5 伏特：

![如何设置电源供应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_19.jpg)

## 交流负载的电源供应

如果我们需要将交流负载连接到 Arduino 或树莓派 Zero 并建立工业控制系统，我们需要使用 24V 直流电压，如下电路图所示：

![交流负载的电源供应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_20.jpg)

## 将 24V 直流继电器连接到 Arduino 板

在下图中，我们有了使用 24 伏特直流继电器控制交流负载的电路：

![将 24V 直流继电器连接到 Arduino 板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_21.jpg)

我们有了最终电路，它代表了连接到 Raspberry Pi Zero 或 Arduino 板的数字引脚的接口，用于控制交流负载：这并不常见，但有必要学习如何将能够用 24 伏特直流通电的继电器连接到 Arduino 板：

![将 24V 直流继电器连接到 Arduino 板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_09_22.jpg)

最后，我们在一个板上有了最终电路。我们使用了一个需要用 24 伏特通电的线圈的继电器。Arduino 或树莓派的数字输出可以连接到继电器模块。

# 摘要

这是书籍《JavaScript 物联网编程》的最后一章。在本章中，您将学习如何整合在项目中需要考虑的所有元素，当您想要将硬件和软件工具应用到我们展示的项目中时。这将帮助您继续开发自己的项目，遵循本书中分享的基础知识。
