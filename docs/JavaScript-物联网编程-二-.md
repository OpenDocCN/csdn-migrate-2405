# JavaScript 物联网编程（二）

> 原文：[`zh.annas-archive.org/md5/98FAEC66467881BC21EC8531C753D4EC`](https://zh.annas-archive.org/md5/98FAEC66467881BC21EC8531C753D4EC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：控制连接的设备

在本章中，我们将看看如何使用我们的 Raspberry Pi Zero 和 Arduino UNO 从远程站点控制设备，使用以下模块在网络中进行通信：Wi-Fi shield 和 Ethernet shield。我们将在本章中涵盖以下主题：

+   使用 Node.js 创建一个简单的 Web 服务器

+   使用 Restful API 和 Node.js 从 Raspberry Pi Zero 控制继电器

+   在计算机上配置 Node.js 作为 Web 服务器

+   使用 Node.js 和 Arduino Wi-Fi 监控温度、湿度和光线

+   使用 Node.js 和 Arduino Ethernet 监控温度、湿度和光线

# 使用 Node.js 创建一个简单的 Web 服务器

拥有 Raspberry Pi 最重要的一个方面是我们有一个配置了服务和服务器的真正的计算机。在本节中，我们将解释如何安装 Node.js，这是一个强大的框架，我们将用它来运行我们将在本书中看到的大多数应用程序。幸运的是，我们在 Raspberry Pi 上安装 Node.js 非常简单。

在本章的文件夹中，打开名为`webserver.js`的文件。我们将在端口*8056*上创建一个服务器。要测试程序并查看结果，我们必须在 MS-DOS 界面上打开 Node.js 终端，并使用以下命令运行此文件：

```js
**node webserver.js**

```

添加以下行到`webserver.js`文件中声明 HTTP 请求命令：

```js
var http = require('http'); 

```

我们使用以下函数创建服务器：

```js
http.createServer(function (req, res) { 

```

我们定义将在 HTML 代码中显示的文件内容：

```js
res.writeHead(200, {'Content-Type': 'text/plain'}); 

```

我们从服务器发送响应：

```js
res.end('Hello  from Node.js'); 

```

重要的是要定义要打开的端口：

```js
}).listen(8056); 

```

显示服务器的消息：

```js
console.log('Server running at port 8056'); 

```

要测试此程序，请在本地计算机上打开浏览器，导航到以下链接：`http://192.168.1.105:8056`。如果您看到以下屏幕；您的 Node.js 服务器在您的计算机上运行正常；您需要更改计算机的 IP 地址：

![使用 Node.js 创建一个简单的 Web 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_01.jpg)

# 使用 Restful API 和 Node.js 从 Raspberry Pi Zero 控制继电器

在本节中，我们将向您展示如何控制连接到 Arduino UNO 板的继电器模块，以及用于从 Web 浏览器发送命令的继电器。让我们开始吧。

## JSON 结构

**JavaScript 对象表示法** **(JSON)** 是一种轻量级的数据交换格式。它易于人类阅读和编写。它易于机器解析和生成。它基于 JavaScript 编程语言的一个子集。

JSON 建立在两种结构上：

+   一组名称/值对。在各种语言中，这被实现为对象、记录、结构、字典、哈希表、键控列表或关联数组。

+   一系列值的有序列表。在大多数语言中，这被实现为数组、向量、列表或序列。

首先，我们需要知道如何应用我们用来描述这个结构的 JSON 格式，如下所示：

```js
{"data": "Pin D6 set to 1", "id": "1", "name": "Arduino", "connected": true}
```

这是我们需要遵循并使响应的格式：

+   **数据：**定义命令的编号，然后描述命令的定义

+   **名称：**跟随设备的名称

+   **已连接：**确认设备是否已连接

所有在`{ }`之间的数据定义了我们的 JSON 格式。

## 使用 aREST API 的命令

使用`aREST`命令，我们可以定义我们的 Arduino 和设备，然后从 Web 浏览器控制它们。以下是`aREST` API 的命令示例：

+   `设备的 IP 地址/模式/6/o`：这将配置数字引脚 6 为输出引脚

+   `设备的 IP 地址/digital/6/1`：配置输出 6 并使函数像数字写入一样。例如：`http://192.168.1.100/digital/6/1`；我们定义设备的 IP 地址和将被激活的引脚的编号。

## 在您的 Raspberry Pi Zero 上安装 Node.js

Node.js 是一个工具，它将允许我们使用 JavaScript 代码在设备上创建运行的服务器。最重要的是，我们将应用这个框架来使用这段代码构建一个 Web 服务器。

使用 Node.js 意味着我们配置了一个将打开端口并连接到 Web 服务器的设备的 Web 服务器。

使用以下命令，您将在树莓派 Zero 上安装 Node.js：

```js
**sudo apt-get install nodejs**

```

NPM 是 Node.js 的 JavaScript 运行时环境的默认包管理器。要配置和安装`aREST`模块，请在终端中输入以下命令：

```js
**sudo npm install arest**

```

Express 的理念是为 HTTP 服务器提供小巧、强大的工具，使其成为单页应用程序、网站、混合应用程序或公共 HTTP API 的绝佳解决方案。

我们还需要使用以下命令配置 express 模块：

```js
**sudo npm install express**

```

# 使用 aREST 命令从 Web 浏览器控制继电器

在接下来的部分中，我们将看到如何使用`Rest`命令从 Web 浏览器控制数字输出。让我们深入了解一下，以了解更多细节：

## 配置 Web 服务器

现在，您可以将代码复制到名为 outputcontrol.js 的文件中，或者只需从此项目的文件夹中获取完整的代码并使用 Node.js 执行它。在树莓派上打开终端并输入以下命令：

```js
**sudo node output control.js**

```

我们通过以下方式定义设备的 GPIO 来导入命令：

```js
var gpio = require('rpi-gpio'); 

```

现在我们将使用以下代码使用 Node.js 创建我们的 Web 服务器。

我们导入运行所需的 require 包。我们使用以下声明库：

```js
var express = require('express'); 
var app = express(); 

```

定义 body 解析器并打开端口，在本例中为*8099*：

```js
var Parser = require('body-parser'); 
var port = 8099; 

```

使用 body-parser：

```js
app.use(Parser.urlencoded({ extended: false })); 
app.use(Parser.json()); 

```

配置**GPIO 11**，我们将控制它：

```js
gpio.setup(11,gpio.DIR_OUT); 

```

我们定义将从 Web 浏览器调用的函数。

函数的名称是`ledon`；它激活**GPIO 11**并向屏幕发送消息`led1 is on`：

```js
function ledon() { 
    setTimeout(function() { 
        console.log('led1 is on'); 
        gpio.write(11, 1); 
      }, 2000); 
} 

```

函数的名称是`ledoff`；它关闭**GPIO 11**并向屏幕发送消息`led1 is off`：

```js
function ledoff() { 
    setTimeout(function() { 
        console.log('led1 is off'); 
        gpio.write(11, 0); 
   }, 2000); 
} 

```

我们定义了`GET`函数，这意味着当浏览器接收到名为`ledon`的函数时，它会向服务器发出请求；服务器以以下格式做出响应：`{status:"connected",led:"on"}`。

现在我们将声明用于来自客户端的传入请求的 app 函数：

```js
app.get('/ledon', function (req, res) { 
    ledon(); 
    var data ={status:"connected",led:"on"}; 
    res.json(data); 
}); 

```

我们定义`GET`函数。这意味着当浏览器接收到名为`/ledoff`的函数时，它会向服务器发出请求；服务器以以下格式做出响应：`{status:"connected",led:"off"}`。

```js
app.get('/ledoff', function (req, res) { 
    ledoff(); 
    var data ={status:"connected",led:"off"}; 
    res.json(data); 
}); 

```

现在我们打开 Web 服务器的端口：

```js
app.listen(port); 
console.log('Server was started on ' + port); 

```

如果一切正确，我们打开我们喜爱的浏览器并输入`http://您的 Raspberry_PI_zero 的 IP 地址:端口/命令`。

`在这种情况下，我们输入 192.168.1.105:8099/ledon`。

以下屏幕截图显示了 JSON 请求的响应：

![配置 Web 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_02.jpg)

接下来，我们将看到最终结果，如下图所示：

![配置 Web 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_03.jpg)

# 在计算机上配置 Node.js 作为 Web 服务器

Node.js 是一个开源的跨平台运行时环境，用于开发服务器端和网络应用程序。Node.js 应用程序是用 JavaScript 编写的，并可以在 OS X、Microsoft Windows 和 Linux 上的 Node.js 运行时环境中运行。

Node.js 还提供了丰富的各种 JavaScript 模块库，极大地简化了使用 Node.js 开发 Web 应用程序的过程。

在上一节中，我们在树莓派 Zero 上配置了 Node.js，现在在本节中，我们将使用 Windows 操作系统执行相同的操作，并配置我们的 Web 服务器 Node.js 在其上运行。

本节的主要目的是解释如何从在 Node.js 框架中运行的 Web 服务器控制我们的 Arduino 板。为此，安装它非常重要；我们的系统将在 Windows 计算机上运行。

在本节中，我们将解释如何在 Windows 上安装 Node.js。

## 下载 Node.js

首先，我们需要下载 Windows 64 位的 Node.js-它取决于您的操作系统版本，您只需要转到以下链接进行下载：[`nodejs.org/es/download/`](https://nodejs.org/es/download/)：

![下载 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_04.jpg)

## 安装 Node.js

在下载了软件之后，按照以下步骤进行：

1.  点击**下一步**按钮：![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_05.jpg)

1.  点击**下一步**按钮：![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_06.jpg)

1.  选择安装位置：![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_07.jpg)

1.  选择默认配置：![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_08.jpg)

1.  完成配置后，点击**安装**：![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_09.jpg)

1.  安装完成后我们将看到以下内容：![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_10.jpg)

## 使用 Node.js 配置 web 服务器端口 8080

现在我们需要配置将要监听来自远程浏览器的打开连接的端口。打开本章文件夹中的文件，然后使用 Node.js 执行该文件。

现在你可以把代码复制到一个名为`server.js`的文件中，或者直接从这个项目的文件夹中获取完整的代码。

首先我们需要使用以下代码创建我们的服务器：

```js
var server = require('http'); 

```

创建一个名为`loadServer`的函数，其中包含响应浏览器的代码：

```js
function loadServer(requiere,response){ 
      console.log("Somebody is connected");     

```

如果这个函数响应数字 200，那么意味着连接已经建立，服务器工作正常：

```js
response.writeHead(200,{"Content-Type":"text/html"}); 
      response.write("<h1>The Server works perfect</h1>"); 
      response.end(); 
} 

```

创建并打开服务器端口：

```js
server.createServer(loadServer).listen(8080); 

```

在你的计算机上打开安装了 Node.js 服务器的终端，然后在 MS-DOS 界面中输入以下命令：

```js
**C:\users\PC>node server.js**

```

现在，为了测试服务器是否运行，我们将在网页浏览器中输入`localhost:端口号`；你应该在屏幕上看到类似以下截图的内容：

```js
http://localhost:8080  

```

![使用 Node.js 配置 web 服务器端口 8080](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_11.jpg)

# 使用 Node.js 和 Arduino Wi-Fi 监控温度、湿度和光线

在本章的这部分，我们将解释 Arduino 的 Wi-Fi shield 的代码：

![使用 Node.js 和 Arduino Wi-Fi 监控温度、湿度和光线](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_12.jpg)

我们定义变量的数量；在这种情况下，我们将监控三个变量（`温度`、`湿度`和`光线`）：

```js
#define NUMBER_VARIABLES 3 

```

这里我们必须包含传感器的库：

```js
#include "DHT.h" 

```

我们定义传感器的引脚：

```js
#define DHTPIN 7  
#define DHTTYPE DHT11 

```

我们定义传感器的实例：

```js
DHT dht(DHTPIN, DHTTYPE); 

```

我们导入模块的库：

```js
#include <Adafruit_CC3000.h> 
#include <SPI.h> 
#include <CC3000_MDNS.h> 
#include <aREST.h> 

```

我们定义连接模块的引脚：

```js
using a breakout board 
#define ADAFRUIT_CC3000_IRQ   3 
#define ADAFRUIT_CC3000_VBAT  5 
#define ADAFRUIT_CC3000_CS    10 

```

我们创建将要连接的模块的实例：

```js
Adafruit_CC3000 cc3000 = Adafruit_CC3000(ADAFRUIT_CC3000_CS,  
ADAFRUIT_CC3000_IRQ, ADAFRUIT_CC3000_VBAT); 

```

我们定义 aREST 实例：

```js
aREST rest = aREST(); 

```

然后我们定义 SSID 和密码，你需要进行更改：

```js
#define WLAN_SSID       "xxxxx" 
#define WLAN_PASS       "xxxxx" 
#define WLAN_SECURITY   WLAN_SEC_WPA2 

```

我们配置端口以监听传入的 TCP 连接：

```js
#define LISTEN_PORT           80 

```

我们定义模块的服务器实例：

```js
Adafruit_CC3000_Server restServer(LISTEN_PORT); 
// DNS responder instance 
MDNSResponder mdns; 

```

我们定义将要发布的变量：

```js
int temp; 
int hum; 
int light; 

```

这里有一个设置，定义了串行通信的配置：

```js
void setup(void) 
{   
  // Start Serial 
  Serial.begin(115200);  
  dht.begin(); 

```

我们开始将要发布的变量：

```js
  rest.variable("light",&light); 
  rest.variable("temp",&temp); 
  rest.variable("hum",&hum); 

```

我们定义设备的 ID 和名称：

```js
  rest.set_id("001"); 
  rest.set_name("monitor"); 

```

我们连接到网络：

```js
  if (!cc3000.begin()) 
  { 
    while(1); 
  } 
  if (!cc3000.connectToAP(WLAN_SSID, WLAN_PASS, WLAN_SECURITY)) { 
    while(1); 
  } 
  while (!cc3000.checkDHCP()) 
  { 
    delay(100); 
  } 

```

这里我们定义了连接设备的函数：

```js
  if (!mdns.begin("arduino", cc3000)) { 
    while(1);  
  } 

```

我们在串行接口中显示连接：

```js
  displayConnectionDetails(); 
  restServer.begin(); 
  Serial.println(F("Listening for connections...")); 
} 

```

在这部分，我们声明将要获取的变量：

```js
void loop() { 
  temp = (float)dht.readTemperature(); 
  hum = (float)dht.readHumidity(); 

```

然后我们测量光线水平：

```js
  float sensor_reading = analogRead(A0); 
  light = (int)(sensor_reading/1024*100); 

```

我们声明请求的函数：

```js
  mdns.update(); 

```

我们需要执行来自服务器的请求：

```js
Adafruit_CC3000_ClientRef client = restServer.available(); 
  rest.handle(client); 
} 

```

我们显示设备的网络配置：

```js
bool displayConnectionDetails(void) 
{ 
  uint32_t ipAddress, netmask, gateway, dhcpserv, dnsserv; 
  if(!cc3000.getIPAddress(&ipAddress, &netmask, &gateway, &dhcpserv, &dnsserv)) 
  { 
Serial.println(F("Unable to retrieve the IP Address!\r\n")); 
    return false; 
  } 
  else 
  { 
    Serial.print(F("\nIP Addr: ")); cc3000.printIPdotsRev(ipAddress); 
    Serial.print(F("\nNetmask: ")); cc3000.printIPdotsRev(netmask); 
    Serial.print(F("\nGateway: ")); cc3000.printIPdotsRev(gateway); 
    Serial.print(F("\nDHCPsrv: ")); cc3000.printIPdotsRev(dhcpserv); 
    Serial.print(F("\nDNSserv: ")); cc3000.printIPdotsRev(dnsserv); 
    Serial.println(); 
    return true; 
  } 
} 

```

在你的 Arduino 板上下载代码草图，然后转到串行监视器以查看从路由器获取的 IP 地址配置。之后，我们可以显示 Wi-Fi shield 的 IP 地址配置：

![使用 Node.js 和 Arduino Wi-Fi 监控温度、湿度和光线](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_13.jpg)

## 连接到 Wi-Fi 网络

现在我们可以看到你的 Arduino Wi-Fi shield 的 IP 地址，我们现在可以将我们的计算机连接到与 Arduino 板相同的网络。查看以下截图以获取更多细节：

![连接到 Wi-Fi 网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_23.jpg)

为了测试应用程序，我们需要转到以下路径，并在安装了 Node.js 服务器的计算机上运行以下命令，或者如下截图所示：

![连接到 Wi-Fi 网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_15.jpg)

在这个文件夹中，我们有 JavaScript 文件，输入命令 node app.js

在输入接口文件夹后，输入以下命令`node app.js`：

![连接到 Wi-Fi 网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_16.jpg)

现在您已经启动了 Web 服务器应用程序，切换到浏览器，在同一台机器上输入机器的 IP 地址以查看结果：

![连接到 Wi-Fi 网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_17.jpg)

服务器监听端口 300 后，它与 Wi-Fi 模块建立通信，向设备的 IP 地址发送请求：

![连接到 Wi-Fi 网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_18.jpg)

# 使用 Node.js 与 Arduino Ethernet 监控温度、湿度和光照

在上一节中，我们展示了如何使用*CC3000*模块通过 Wi-Fi 监视我们的 Arduino；现在我们将使用另一个重要模块：以太网盾。部分的硬件连接类似于以下图像：

![使用 Node.js 与 Arduino Ethernet 监控温度、湿度和光照](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_19.jpg)

## Arduino Ethernet 盾应用程序代码

现在您可以将代码复制到名为`Monitor_Ethernet.ino`的文件中，或者只需从此项目的文件夹中获取完整的代码；您需要使用 Arduino IDE。

以下是程序中包含的库：

```js
#include <SPI.h> 
#include <Ethernet.h> 
#include <aREST.h> 
#include <avr/wdt.h> 

```

包括 DHT11 传感器的库：

```js
#include "DHT.h" 

```

我们定义温度和湿度传感器的引脚：

```js
#define DHTPIN 7  
#define DHTTYPE DHT11 

```

我们有传感器的实例：

```js
DHT dht(DHTPIN, DHTTYPE); 

```

我们注册设备的 MAC 地址：

```js
byte mac[] = { 0x90, 0xA2, 0xDA, 0x0E, 0xFE, 0x40 }; 
IPAddress ip(192,168,1,153); 
EthernetServer server(80); 

```

我们现在创建`aREST` API 的实例：

```js
aREST rest = aREST(); 

```

我们发布将被监视的变量：

```js
int temp; 
int hum; 
int light; 

```

我们现在配置串行通信并启动传感器的实例：

```js
void setup(void) 
{   
  // Start Serial 
  Serial.begin(115200); 
  dht.begin(); 

```

我们开始发布变量：

```js
  rest.variable("light",&light); 
  rest.variable("temp",&temp); 
  rest.variable("hum",&hum); 

```

非常重要的是给出我们正在使用的设备的 ID 和名称：

```js
  rest.set_id("008"); 
  rest.set_name("Ethernet"); 

```

我们开始以太网连接：

```js
if (Ethernet.begin(mac) == 0) { 
    Serial.println("Failed to configure Ethernet using DHCP"); 
    Ethernet.begin(mac, ip); 
  } 

```

我们在串行监视器上显示 IP 地址：

```js
  server.begin(); 
  Serial.print("server is at "); 
  Serial.println(Ethernet.localIP()); 
  wdt_enable(WDTO_4S); 
} 

```

我们读取温度和湿度传感器：

```js
void loop() {   

  temp = (float)dht.readTemperature(); 
  hum = (float)dht.readHumidity(); 

```

我们测量传感器的光照水平：

```js
  float sensor_reading = analogRead(A0); 
  light = (sensor_reading/1024*100); 

```

我们监听将连接的传入客户端：

```js
  EthernetClient client = server.available(); 
  rest.handle(client); 
  wdt_reset(); 
} 

```

现在我们已经完成了配置，打开一个网络浏览器并输入您的 Arduino Ethernet 盾的 IP 地址：`http://192.168.1.153`。如果一切顺利，它将显示以下屏幕，并显示来自板的 JSON 响应：

![Arduino Ethernet 盾应用程序代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_20.jpg)

上述截图显示了 JSON 请求的结果。

## 在 Node.js 中配置设备

在本节中，我们将解释配置我们可以从网页控制的设备的代码。

在上一节中，我们安装了 express 包；如果遇到任何困难，只需打开终端并输入以下内容：

```js
**npm install express**

```

我们定义节点 express 并创建应用程序：

```js
var express = require('express'); 
var app = express(); 

```

然后我们定义要监听的端口：

```js
var port = 3000; 

```

我们定义 Jade 应用程序的实例，使用视图引擎：

```js
app.set('view engine', 'jade'); 

```

我们配置公共文件夹：

```js
app.use(express.static(__dirname + '/public')); 

```

我们现在定义要监视的设备：

```js
var rest = require("arest")(app); 
rest.addDevice('http','192.168.1.153'); 

```

我们提供应用程序：

```js
app.get('/', function(req, res){ 
res.render('interface'); 
}); 

```

我们启动服务器并在设备连接时发送消息：

```js
app.listen(port); 
console.log("Listening on port " + port); 

```

在 MS-DOS 中打开终端并在 Node.js 服务器中执行`app.js`

要测试应用程序，请打开您的网络浏览器并输入`http://localhost:3000`；如果出现以下屏幕，恭喜，您已正确配置了服务器：

![在 Node.js 中配置设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_21.jpg)

这里是我们在 Node.js 服务器中看到`app.js`执行的屏幕：

![在 Node.js 中配置设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_04_22.jpg)

# 摘要

在本章中，您学习了如何使用树莓派 Zero 中的网络通信模块来控制 Arduino 板，在中央界面仪表板中。我们已经看到了如何从中央界面控制和监视设备；您可以使用其他传感器，例如气压传感器。

在下一章中，您将进行更多有趣的项目，例如将网络摄像头配置和连接到您的 Arduino 板，从您的 Raspberry Pi Zero 上进行监控。


# 第五章：将网络摄像头添加到监控安全系统

在之前的章节中，我们谈到了诸如连接到 Arduino 的传感器和从树莓派 Zero 监控，使用跨设备的网络，家庭安全项目的重要性以及家居自动化来监视现实世界中发生的事情。为此，我们为本章提出了一个建议。

在本章中，我们将配置我们的树莓派 Zero 来监视网络摄像头，并安装 TTL 串行摄像头以与 Arduino 板交互；我们将通过以下主题实现这一目标：

+   Arduino 和树莓派之间的交互

+   从树莓派 Zero 控制连接到 Arduino 的输出

+   将 TTL 串行摄像头连接到 Arduino 并将图片保存到 Micro SD

+   使用串行 TTL 摄像头检测运动

+   从树莓派控制快照

+   从网页控制您的摄像头

+   在网络中监控您的 USB 摄像头以确保安全

# Arduino 和树莓派之间的交互

在本章中，我们将看看树莓派如何作为终端计算机来编程，不仅可以将设备作为服务器并部署页面或应用程序，还可以拥有用于编程 Arduino 板的集成开发环境。为此，我们需要将树莓派连接到 Arduino，以便它们可以相互通信。

这里有一些树莓派具有的接口，所有这些都包括在设备中：I2C 协议，SPI 通信，USB 端口和串行**UART**端口。在这种情况下，我们将使用 USB 端口在 Arduino 和树莓派之间进行通信。

以下是配置 Arduino 和树莓派相互交互的步骤：

1.  为树莓派安装 Arduino IDE

1.  用 PuTTY 打开您的终端并检查树莓派的 IP 地址

1.  执行远程访问，并输入 IP 地址

1.  在图形界面中打开 Arduino IDE

## 在 Raspbian 中安装 Arduino IDE

输入以下命令在树莓派上安装 Arduino IDE：

```js
**sudo apt-get install arduino**

```

## 远程访问树莓派

在本节中，我们将查看访问远程桌面的屏幕，以执行安装在 Raspian 操作系统中的 Arduino IDE：一旦屏幕弹出，输入您的用户名和密码：

![远程访问树莓派](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_01.jpg)

## 在图形界面中执行 Arduino

现在我们有了主屏幕，我们转到**编程**菜单，如果我们看到进入 Arduino IDE 的图标，那么一切都已安装。点击**Arduino IDE**的图标：

![在图形界面中执行 Arduino](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_02.jpg)

# Raspian 中的 Arduino 界面

这里有 Arduino IDE 的界面，与我们在计算机上拥有的界面类似。从在树莓派上运行的 Arduino IDE 中，我们可以在两个板之间进行交互：

![Raspian 中的 Arduino 界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_03.jpg)

## 准备界面

我们需要验证我们选择了正确的板；在这种情况下，我们使用的是 Arduino UNO。在下一个窗口中选择板：

![准备界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_04.jpg)

## 选择串行端口

在我们选择要使用的板之后，我们需要验证并选择将与我们的 Arduino 通信的端口，该端口连接到树莓派的 USB 端口上；我们需要选择端口名称：`/dev/ttyACM0`：

![选择串行端口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_05.jpg)

## 从图形界面下载草图

我们需要做的主要事情是从我们的树莓派 Zero 与 Arduino 进行通信，并将草图下载到 Arduino 板上，而不使用计算机，以便我们可以将树莓派用于其他目的。

以下截图显示了带有草图的界面：

![从图形界面下载草图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_06.jpg)

我们应该在界面中下载草图。以下图片显示了连接的 Arduino-树莓派：太酷了！

![从图形界面下载草图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_05_007.jpg)

# 从 Raspberry Pi Zero 控制连接到 Arduino 的输出

现在我们将看一个例子，使用 Python 从 Raspberry Pi 控制输出。

首先，我们需要将 sketch 下载到 Arduino 板上。为了测试我们的通信，我们将展示一个测试 Arduino 和 Raspberry Pi 之间链接的示例：

我们声明以下输出：

```js
int led_output = 13; 

```

我们从程序设置开始：

```js
void setup () { 

```

然后我们提到输出引脚：

```js
pinMode(led_output, OUTPUT); 

```

以 9600 开始串行通信：

```js
Serial.begin(9600); 
} 

```

声明程序的循环：

```js
void loop () {
```

这是我们检查串行端口是否可用的地方：

```js
if (Serial.available() > 0){ 

```

如果找到了某些内容，则读取内容并将内容保存在`c`变量中：

```js
char c = Serial.read(); 

```

如果读取了标记为高的字母`H`：

```js
      if (c == 'H'){ 

```

输出将打开连接到引脚**13**的 LED

```js
digitalWrite(led_output, HIGH); 

```

如果读取了标记为低的字母`L`：

```js
}  
else if (c == 'L'){ 

```

输出将关闭连接到引脚**13**的 LED：

```js
         digitalWrite(led_output, LOW); 
      }  
   } 
} 

```

# 从 Python 控制 Arduino 板

首先，我们需要安装串行库，因为这有助于通过 USB 端口通信与 Arduino 通信。键入以下命令以安装库：

```js
**sudo apt-get install python-serial**

```

以下代码控制 Arduino 来自 Raspberry Pi；现在您可以将代码复制到名为`ControlArduinoFromRasp.py`的文件中，或者只需从此项目的文件夹中获取完整的代码。

以下片段在 Python 中导入串行库：

```js
import serial 

```

我们定义串行通信：

```js
Arduino_UNO = serial.Serial('/dev/ttyACM0', 9600) 

```

打印一条消息以查看通信是否完成：

```js
print("Hello From Arduino!") 

```

在执行此操作时，用户可以输入命令：

```js
while True: 
      command = raw_input('Enter the command ') 
      Arduino_UNO.write(command) 

```

如果是`H`，它会打印消息；如果为假，则显示 LED 关闭：

```js
      if command == 'H': 
            print('LED ON') 
      elif command == 'L': 
            print('LED OFF') 

```

关闭连接：

```js
arduino_UNO.close() 

```

## 硬件连接

这是连接到 Arduino UNO 的 LED，可以使用 Python 从 Raspberry Pi 进行控制：

![硬件连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_08.jpg)

# 将 TTL 串行相机连接到 Arduino 并将照片保存到微型 SD 卡

在这里，我们有模式图，显示了微型 SD 卡与 TTL 串行相机的连接；我使用的是 Adafruit 的相机型号。以下链接包含您需要的所有信息，[`www.adafruit.com/product/397`](https://www.adafruit.com/product/397)。在下图中，我们有项目的连接：

![将 TTL 串行相机连接到 Arduino 并将照片保存到微型 SD 卡](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_05_009.jpg)

现在我们将解释如何拍照并将其保存到微型 SD 卡；主要想法是将相机连接到 Arduino，这样我们可以在家庭安全监控系统中实现这一点。

以下是用于测试 TTL 相机、拍照并将其保存在微型 SD 卡上的代码。请注意，代码太长，但我将解释执行先前操作所需的最重要和必要的代码。所有这些示例的代码都包含在书中，以获取更完整的信息。

在这里，我们从 TTL 相机导入文件，并与微型 SD 卡通信的文件：

```js
#include <Adafruit_VC0706.h> 
#include <SPI.h> 
#include <SD.h> 

```

我们定义软件库以通过串行通信：

```js
// comment out this line if using Arduino V23 or earlier 
#include <SoftwareSerial.h>        

```

将`chipSelect`定义为引脚 10：

```js
#define chipSelect 10 

```

代码将用于连接引脚：

```js
SoftwareSerial cameraconnection = SoftwareSerial(2, 3); 
Adafruit_VC0706 cam = Adafruit_VC0706(&cameraconnection); 

```

然后我们需要启动相机：

```js
  if (cam.begin()) { 
    Serial.println("Camera Found:"); 
  } else { 
    Serial.println("No camera found?"); 
    return; 
  } 

```

在这里我们定义图像大小：

```js
    cam.setImageSize(VC0706_640x480); 

```

这将显示图像大小：

```js
  uint8_t imgsize = cam.getImageSize(); 
  Serial.print("Image size: "); 

```

代码将拍照：

```js
  if (! cam.takePicture())  
    Serial.println("Failed to snap!"); 
  else  
    Serial.println("Picture taken!"); 

```

创建文件以保存所拍摄的图像：

```js
  char filename[13]; 

```

保存文件的代码：

```js
  strcpy(filename, "IMAGE00.JPG"); 
  for (int i = 0; i < 100; i++) { 
    filename[5] = '0' + i/10; 
    filename[6] = '0' + i%10; 

```

准备微型 SD 卡以保存文件：

```js
if (! SD.exists(filename)) { 
      break; 
    } 
  } 

```

打开拍摄的文件进行预览：

```js
  File imgFile = SD.open(filename, FILE_WRITE); 

```

显示所拍摄图像的大小：

```js
  uint16_t jpglen = cam.frameLength(); 
  Serial.print("Storing "); 
  Serial.print(jpglen, DEC); 
  Serial.print(" byte image."); 

```

从文件中读取数据：

```js
  byte wCount = 0; // For counting # of writes 
  while (jpglen > 0) { 

```

将文件写入内存：

```js
    uint8_t *buffer; 
    uint8_t bytesToRead = min(32, jpglen); 
    buffer = cam.readPicture(bytesToRead); 
    imgFile.write(buffer, bytesToRead); 

```

在屏幕上显示文件：

```js
    if(++wCount >= 64) { 
      Serial.print('.'); 
      wCount = 0; 
    } 

```

显示读取的字节数：

```js
Serial.print(bytesToRead, DEC);  
Serial.println(" bytes"); 
jpglen -= bytesToRead; 
  } 

```

关闭打开的文件：

```js
imgFile.close(); 

```

# 使用串行 TTL 相机检测运动

打开 TTL 相机的运动检测：

```js
  cam.setMotionDetect(true); 

```

验证运动是否激活：

```js
  Serial.print("Motion detection is "); 
  if (cam.getMotionDetect())  
    Serial.println("ON"); 
  else  
    Serial.println("OFF"); 
} 

```

当相机检测到运动时会发生什么：

```js
if (cam.motionDetected()) { 
   Serial.println("Motion!");    
   cam.setMotionDetect(false); 

```

如果检测到运动，则拍照或显示消息：

```js
  if (! cam.takePicture())  
    Serial.println("Failed to snap!"); 
  else  
    Serial.println("Picture taken!"); 

```

# 从 Raspberry Pi 控制快照

现在我们已经看到了如何在 Arduino 和 Raspberry Pi 之间进行通信，以控制板，我们可以将其应用于我们的安全系统项目。我们需要这样做以便从 Raspberry Pi 与控制我们的相机进行通信：

+   将 Arduino 和树莓派连接在一起

+   以 9,600 mbps 创建串行连接

+   调用将拍照并保存在微型 SD 卡中的函数

在树莓派上，我们需要做以下事情：

+   创建调用在 Arduino 中拍照的函数的脚本

+   使用 PuTTY 终端打开并执行脚本

以下部分是应下载到 Arduino 板中的草图：

首先我们开始串行通信：

```js
void setup () { 
    Serial.begin(9600);  
} 

```

这是将告诉摄像头拍照的函数：

```js
void loop () { 
   if (Serial.available() > 0) { 
      char c = Serial.read(); 
      if (c == 'T') {  

      takingpicture(): 

      }  
   } 
} 

```

## 拍照功能的代码

在这里我们讨论定义将提示摄像头拍照的函数的代码。

该函数包含将拍照的代码：

```js
void takingpicture(){ 

```

拍照：

```js
  if (!cam.takePicture())  
    Serial.println("Failed to snap!"); 
  else  
    Serial.println("Picture taken!"); 

```

在这里我们创建保存文件：

```js
  char filename[13]; 

```

在这里我们保存文件：

```js
  strcpy(filename, "IMAGE00.JPG"); 
  for (int i = 0; i < 100; i++) { 
    filename[5] = '0' + i/10; 
    filename[6] = '0' + i%10; 

```

准备微型 SD 卡保存文件：

```js
if (! SD.exists(filename)) { 
      break; 
    } 
  } 

```

打开文件进行预览：

```js
  File imgFile = SD.open(filename, FILE_WRITE); 

```

在保存之前获取文件的大小：

```js
  uint16_t jpglen = cam.frameLength(); 
  Serial.print("Storing "); 
  Serial.print(jpglen, DEC); 
  Serial.print(" byte image."); 

```

从保存的文件中读取数据：

```js
  byte wCount = 0; // For counting # of writes 
  while (jpglen > 0) { 

```

将文件写入内存：

```js
    uint8_t *buffer; 
    uint8_t bytesToRead = min(32, jpglen); 
    buffer = cam.readPicture(bytesToRead); 
    imgFile.write(buffer, bytesToRead); 

```

保存后显示文件：

```js
    if(++wCount >= 64) { 
      Serial.print('.'); 
      wCount = 0; 
    } 

```

显示读取的字节数：

```js
Serial.print(bytesToRead, DEC);  
Serial.println(" bytes"); 
jpglen -= bytesToRead; 
  } 

```

关闭已打开的文件：

```js
imgFile.close(); 
}
```

# 从网页上控制您的摄像头

在这一部分，我们将看看如何从 PHP 的网页上控制我们的摄像头，并在树莓派上运行一个 Web 服务器。我们需要以下内容来运行 PHP 文件和 Web 服务器：

+   在树莓派上运行 Apache 服务器

+   安装 PHP 软件

对于控制的网页，我们需要在以下路径创建我们的 PHP 文件：`/var/www/html`，例如我们需要编辑`index.php`文件，并复制以下行。

以下 HTML 文件包括 PHP：

```js
<!DOCTYPE html> 
<html> 
 <head> 
 <title>Control Camera</title> 
 </head> 
  <body> 

```

在这里我们定义了执行拍照动作的函数：

```js
<form  action="on.php">   
  <button type="submit">Taking the picture</button> 
  </form> 

```

在这里我们定义如果检测到运动要采取的动作：

```js
  <form action="off.php">   
  <button type="submit">Motion</button> 
  </form> 
</body> 
</html> 

```

## 从 PHP 调用 Python 脚本

在这一部分，我们需要从网页调用 Python 脚本并执行包含脚本的文件：

```js
<?php 
$prende= exec('sudo python on.py'); 
header('Location:index.php'); 
?> 

<?php 
$apaga = exec('sudo python motion.py'); 
header('Location:index.php'); 
?> 

```

## Python 脚本的代码

在服务器端，也就是树莓派上，我们有将从网页调用的 Python 脚本：

```js
import serial 
import time 
Arduino_1 = serial.Serial('/dev/ttyACM0',9600) 
Arduino_1.open() 
Command='H' 
if command:    
    Arduino_1.write(command) 
Arduino_1.close() 

import serial 
import time 
Arduino_1 = serial.Serial('/dev/ttyACM0',9600) 
Arduino_1.open() 
Command='L' 
if command:    
    Arduino_1.write(command) 
Arduino_1.close() 

```

如果一切都配置完美，以下页面将出现：在你喜欢的浏览器中，输入你的`PI/index.php`的 IP 地址：

![Python 脚本的代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_10.jpg)

# 在网络中监控您的 USB 摄像头安全

在这一部分，我们将创建一个项目，允许我们监控连接到 Arduino YUN 的 USB 摄像头，它具有 USB 端口并包括以太网和 Wi-Fi 通信。因此，它有许多优势。我们将致力于在树莓派和 Arduino YUN 之间建立一个网络，所以主要的想法是从树莓派的网页上监控摄像头。该页面将存储在树莓派上。

## 配置 Arduino YUN

我们将使用支持 UVC 协议的罗技摄像头：

![配置 Arduino YUN](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_11-1.jpg)

现在我们将解释安装我们的摄像头在 Arduino YUN 中的步骤：

+   将板连接到您的 Wi-Fi 路由器

+   验证 Arduino YUN 的 IP 地址

在我们输入 IP 地址后，将出现以下屏幕：

![配置 Arduino YUN](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_12-1.jpg)

我们现在将在命令提示符下发出一系列命令来完成设置：

更新软件包：

```js
**opkg update**

```

安装 UVC 协议：

```js
**opkg install kmod-video-uvc**

```

安装摄像头驱动程序：

```js
**opkg install fswebcam**

```

下载`Mjpgstreamer`：

```js
**wget http://www.custommobileapps.com.au/downloads/mjpgstreamer.Ipk**

```

安装`Mjpgstreamer`：

```js
**opkg install mjpg-streamer.ipk**

```

要手动启动摄像头，使用以下代码：

```js
**mjpg_streamer -i "input_uvc.so -d /dev/video0 -r 640x480 -f 25" -o**
**"output_http.so -p 8080 -w /www/webcam" &**

```

要自动启动摄像头，我们将使用以下代码：

安装`nano`程序：

```js
**opkg install nano**

```

输入以下文件：

```js
**nano /etc/config/mjpg-streamer**

```

使用以下参数配置摄像头：

```js
config mjpg-streamer core   
option enabled    "1"   
option device    "/dev/video0"   
option resolution  "640x480"   
option fps    "30"   
option www    "/www/webcam"   
option port    "8080" 

```

使用以下命令启动服务：

```js
**/etc/init.d/mjpg-streamer enable**
**/etc/init.d/mjpg-streamer stop**
**/etc/init.d/mjpg-streamer start**

```

## 从 MJPG-STREAMER 服务器监控

一旦你访问了 Arduino YUN 的服务器，就在你的网络浏览器中输入你的 Arduino YUN 的 IP 地址`http://Arduino.local:8080`。配置的结果如下截图所示：

![从 MJPG-STREAMER 服务器监控](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_13.jpg)

## 从树莓派监控 USB 摄像头

连接到 Arduino YUN 的摄像头，现在我们可以实时监控树莓派上发布的网页。

为网页提供一个标题：

```js
<html> 
<head> 
<title>Monitoring USB Camera</title> 

```

我们通过输入 Arduino YUN 的 IP 地址来调用摄像头图像：

```js
</head> 
<body> 
<center> 
<img src="http://192.168.1.107:8080/?action=stream"/> 
</center> 
</body> 
</html> 

```

通过在浏览器中输入树莓派的 IP 地址（`http://192.168.1.106/index.html`）访问网页：

![从树莓派监控 USB 摄像头](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_05_14.jpg)

在下一节中，我们将看如何配置连接的设备和将在网络中进行交互的硬件。

以下图片代表了我们用可以监控的设备创建的网络；例如，我们监控房子的每个房间，将所有设备连接到一个 Wi-Fi 网络，并从树莓派上监控它们：

![从树莓派监控 USB 摄像头](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_05_015.jpg)

# 摘要

在本章中，您已经学会了如何配置连接到网络的网络摄像头，并监控物联网安全系统。我们使用 Arduino 板连接安全摄像头，并将连接到网络的树莓派 Zero 用于监控系统。在下一章中，我们将集成我们的系统，将树莓派 Zero 与 Arduino 连接，构建一个完整的系统连接设备并进行监控。


# 第六章：从仪表板构建 Web 监视器和控制设备

在本章中，我们将讨论本书非常重要的一部分，即创建一个可以从仪表板控制不同类型设备的网页。在自动化的家庭中，有不同类型的设备可以被控制，例如：灯、门或窗户、洗衣机等等。

在本章中，我们将涵盖以下主题：

+   配置 MySQL 数据库服务器

+   安装 PhpMyAdmin 以管理数据库

+   带有 MySQL 的数据记录器

+   调光 LED

+   控制直流电机的速度

+   使用电路控制灯光

+   控制门锁

+   控制浇水的植物

+   从任何地方远程访问您的 Raspberry Pi Zero

+   控制灯光和测量电流消耗

+   从 Raspberry Pi Zero 控制和监视 Arduino、Wi-Fi 和以太网 shield、连接的设备和传感器

# 配置 MySQL 数据库服务器

在本节中，您将学习如何配置 MySQL 服务器，以创建数据库并将所有内容集成到您的仪表板中，以记录数据库中的数据。

## 安装 MySQL

我们的 Raspberry Pi Zero 正在配置为 Web 服务器。在本节中，我们将使用以下命令安装 MySQL 数据库服务器，以便我们可以接收来自客户端的连接，显示存储在数据库中的数据，并在 SQL 中使用查询：

```js
**sudo apt-get install mysql-server**

```

![安装 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_01.jpg)

在过程中它会要求您输入`root`用户的密码：

![安装 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_02.jpg)

安装完成后，连接到 MySQL 并键入以下命令：

```js
**mysql -u root -p**

```

![安装 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_03.jpg)

键入以下命令：

```js
**show databases;**

```

![安装 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_04.jpg)

在这里，我们可以看到现在安装在服务器上的系统数据库：

![安装 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_05.jpg)

## 为 PHP 安装 MySQL 驱动程序

重要的是安装我们的驱动程序以使 PHP5 与 MySQL 数据库服务器通信，为此我们需要 MySQL 驱动程序以访问 MySQL 数据库，执行此命令以安装`PHP-MySQL`驱动程序。

```js
**sudo apt-get install php5 php5-mysql** 

```

## 测试 PHP 和 MySQL

在本节中，我们将使用以下命令创建一个简单的页面来测试 PHP 和 MySQL：

```js
**sudo nano /var/www/html/hellodb.php**

```

![测试 PHP 和 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_06.jpg)

以下屏幕截图显示了包含访问数据库的代码、连接到服务器并从中获取数据的脚本：

![测试 PHP 和 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_07.jpg)

要测试页面和 PHP 与 MySQL 之间的连接，请键入您的 Raspberry Pi 的 IP 地址：`http://192.168.1.105/hellodb.php`。页面应该类似于以下屏幕截图：

![测试 PHP 和 MySQL](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_08.jpg)

# 安装 PhpMyAdmin 以管理数据库

在本节中，我们将讨论如何配置您的 PhpMyAdmin 以从远程面板管理您的数据库。重要的是我们在 Apache 服务器中安装客户端和模块 PHP5，因此键入以下命令：

```js
**sudo apt-get install mysql-client php5-mysql** 

```

接下来，我们将使用以下命令安装`phpmyadmin`软件包：

```js
**sudo apt install phpmyadmin**

```

在下面的屏幕截图中，我们可以看到服务器的配置；在这种情况下，我们需要选择**apache2**：

![为管理数据库安装 PhpMyAdmin](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_09.jpg)

我们选择 apache2 服务器：

![为管理数据库安装 PhpMyAdmin](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_10.jpg)

之后我们可以选择数据库：

![为管理数据库安装 PhpMyAdmin](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_11.jpg)

我们选择**<No>**选项：

![为管理数据库安装 PhpMyAdmin](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_12.jpg)

## 配置 Apache 服务器

我们需要对文件`apache2.conf`进行配置。首先转到您的 Pi 上的终端：

```js
**sudo nano /etc/apache2/apache2.conf**

```

在下一个屏幕上，我们需要添加代码：

```js
**Include /etc/phpmyadmin/apche.conf**

```

![配置 Apache 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_13.jpg)

我们在文件底部包含以下行：

```js
**Include /etc/phpmyadmin/apche.conf**

```

![配置 Apache 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_14.jpg)

我们终于完成了安装我们的 Apache 服务器，现在我们已经准备好进行下一步了。

## 进入 phpMyAdmin 远程面板

在配置了服务器之后，我们将进入 phpMyAdmin 远程面板，我们需要打开我们喜欢的网络浏览器，并输入我们的树莓派的 IP 地址：`http://(树莓派地址)/phpmyadmin`，这将显示以下屏幕：

![进入 phpMyAdmin 远程面板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_15.jpg)

## 显示 Arduinobd 数据库

以下截图显示了在服务器中创建的数据库：

![显示 Arduinobd 数据库](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_16.jpg)

以下截图显示了表**measurements**，列**id**，**temperature**和**humidity**：

![显示 Arduinobd 数据库](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_17.jpg)

## 从 Arduino 和以太网盾发送数据到 Web 服务器

我们使用 Arduino 和连接到网络的以太网盾，Arduino 将数据发送到树莓派 Zero 上发布的 Web 服务器。

您现在可以将代码复制到名为`arduino_xaamp_mysql.ino`的文件中，或者只需从本书的代码文件夹中获取完整的代码：

我们输入 Arduino UNO 的 IP 地址：

```js
IPAddress ip(192,168,1,50); 

```

我们配置了我们的树莓派 Zero 的 IP 地址：

```js
IPAddress server(192,168,1,108); 

```

我们需要连接到 Web 服务器：

```js
if (client.connect(server, 80)) 

```

这些行定义了从远程服务器发出的 HTTP 请求：

```js
client.println("GET /datalogger1.php?temp=" + temp + "&hum=" + hum + " HTTP/1.1"); 
      client.println("Host: 192.168.1.108"); 
      client.println("Connection: close"); 
      client.println(); 

```

其余的代码显示在以下行中：

```js
// Include libraries 
#include <SPI.h> 
#include <Ethernet.h> 
#include "DHT.h" 
// Enter a MAC address for your controller below. 
byte mac[] = { 0x90, 0xA2, 0xDA, 0x0E, 0xFE, 0x40 }; 
// DHT11 sensor pins 
#define DHTPIN 7  
#define DHTTYPE DHT11 
IPAddress ip(192,168,1,50); 
IPAddress server(192,168,1,108); 
EthernetClient client; 
DHT dht(DHTPIN, DHTTYPE); 
void setup() { 
  // Open serial communications 
  Serial.begin(9600); 
      Ethernet.begin(mac, ip); 
  Serial.print("IP address: "); 
  Serial.println(Ethernet.localIP()); 
  delay(1000); 
  Serial.println("Conectando..."); 

} 
void loop() 
{ 
  float h = dht.readHumidity(); 
  float t = dht.readTemperature(); 
  String temp = String((int) t); 
  String hum = String((int) h); 
    if (client.connect(server, 80)) { 
    if (client.connected()) { 
      Serial.println("conectado"); 

```

发出 HTTP 请求：

```js
      client.println("GET /datalogger1.php?temp=" + temp + "&hum=" + hum + " HTTP/1.1"); 
      client.println("Host: 192.168.1.108"); 
      client.println("Connection: close"); 
      client.println(); 
    }  
    else { 
      // If you didn't get a connection to the server 
      Serial.println("fallo la conexion"); 
    } 

```

这些行定义了客户端实例如何读取响应：

```js
    while (client.connected()) { 
      while (client.available()) { 
      char c = client.read(); 
      Serial.print(c); 
      } 
    } 

```

如果服务器断开连接，停止客户端：

```js
    if (!client.connected()) { 
      Serial.println(); 
      Serial.println("desconectado."); 
      client.stop(); 
    } 
  } 

```

每秒重复一次：

```js
  delay(5000); 
} 

```

在这里我们可以看到我们使用的硬件：

![从 Arduino 和以太网盾发送数据到 Web 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_18.jpg)

# 带有 MySQL 的数据记录器

在接下来的部分，我们将构建一个数据记录器，它将记录服务器中的温度和湿度数据，以便我们随时可以获取数据并在网页中显示。

## 编程脚本软件

在下面的代码中，我们有一个将与 Arduino 板通信的脚本，并且它已安装在服务器上。

您现在可以将代码复制到名为`datalogger1.php`的文件中，或者只需从本项目的文件夹中获取完整的代码：

```js
<?php 
if (isset($_GET["temp"]) && isset($_GET["hum"])) { 
$temperature = intval($_GET["temp"]); 
$humidity = intval($_GET["hum"]); 
$con=mysql_connect("localhost","root","ruben","arduinobd"); 
mysql_select_db('arduinobd',$con); 
      if(mysql_query("INSERT INTO measurements (temperature, humidity) VALUES ('$temperature', '$humidity');")){ 
        echo "Data were saved"; 
      } 
      else { 
      echo "Fail the recorded data"; 
      } 
mysql_close($con); 
} 
?> 

```

## 测试连接

安装了脚本文件后，我们需要在您的计算机上打开一个网络浏览器，并输入您的树莓派的 IP 地址 `Raspberry Pi/datalogger1.php?temp=70&hum=100`，链接看起来像 **(http://192.168.1.108/datalogger1.php?temp=70&hum=100)**：

![测试连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_19.jpg)

以下截图显示了保存在数据库中的数据的结果：

![测试连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_20.jpg)

以下截图显示了数据表格：

![测试连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_21.jpg)

# 从数据库查询数据

记录数据并进行一些查询以在网页中显示数据非常重要。

## 脚本软件

这里有我们用来在页面中显示数据的脚本：

您现在可以将代码复制到名为`query1.php`的文件中，或者只需从本项目的文件夹中获取完整的代码：

```js
<!DOCTYPE html> 
  <html> 
    <body> 
<h1>Clik on the buttons to get Data from  MySQL</h1> 
<form action="query1.php" method="get"> 
<input type="submit" value="Get all Data">  
</form> 
</br> 

<form action="query2.php" method="get"> 
<input type="submit"value="Humidity <= 15"> 
</form>  
</br> 

<form action="query3.php" method="get"> 
<input type="submit" value="Temperature <=25">  
</form> 
</br> 
<?php 

$con=mysql_connect("localhost","root","ruben","arduinobd"); 
mysql_select_db('arduinobd',$con); 
$result = mysql_query("SELECT * FROM measurements"); 
echo "<table border='1'> 
<tr> 
<th>Measurements</th> 
<th>Temperature (°C)</th> 
<th>Humidity (%)</th> 
</tr>"; 
while($row = mysql_fetch_array($result)) { 
  echo "<tr>"; 
  echo "<td>" . $row['id'] . "</td>"; 
  echo "<td>" . $row['temperature'] . "</td>"; 
  echo "<td>" . $row['humidity'] . "</td>"; 
  echo "</tr>"; 
} 
echo "</table>"; 
mysql_close($con); 
?> 
</body> 
</html> 

```

在以下截图中，我们有数据：

![脚本软件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_22.jpg)

## 特定数据的脚本以显示

在接下来的几行中，我们可以看到我们可以进行一些 SQL 查询，以获取特定数值的信息，并从温度和湿度中获取数值：

```js
<?php 
$con=mysql_connect("localhost","root","ruben","arduinobd"); 
mysql_select_db('arduinobd',$con); 
$result = mysql_query("SELECT * FROM measurements where humidity <= 15 order by id"); 
echo "<table border='1'> 
<tr> 
<th>Measurements</th> 
<th>Temperature (°C)</th> 
<th>Humidity (%)</th> 
</tr>"; 
while($row = mysql_fetch_array($result)) { 
  echo "<tr>"; 
  echo "<td>" . $row['id'] . "</td>"; 
  echo "<td>" . $row['temperature'] . "</td>"; 
  echo "<td>" . $row['humidity'] . "</td>"; 
  echo "</tr>"; 
} 
echo "</table>"; 
mysql_close($con); 
?> 

```

## 查询记录温度

在本节中，我们将创建一个查询以获取温度测量值。我们将服务器引用称为`localhost`，在本例中是树莓派零设备，用户和数据库的名称：

```js
<?php 
$con=mysql_connect("localhost","root","ruben","arduinobd"); 
mysql_select_db('arduinobd',$con); 
$result = mysql_query("SELECT * FROM measurements where temperature <= 25 order by id"); 
echo "<table border='1'> 
<tr> 
<th>Measurements</th> 
<th>Temperature (°C)</th> 
<th>Humidity (%)</th> 
</tr>"; 
while($row = mysql_fetch_array($result)) { 
  echo "<tr>"; 
  echo "<td>" . $row['id'] . "</td>"; 
  echo "<td>" . $row['temperature'] . "</td>"; 
  echo "<td>" . $row['humidity'] . "</td>"; 
  echo "</tr>"; 
} 
echo "</table>"; 
mysql_close($con); 
?> 

```

查询结果显示在以下截图中：

![查询记录温度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_23.jpg)

# 控制和调光 LED

在本节中，我们将讨论一个可以应用于家庭自动化的项目。我们将调暗直流 LED，这可以应用于房子里的灯。LED 将改变亮度，并且我们将 LED 连接到树莓派的**GPIO18**，并串联一个*330*欧姆的电阻。

## 软件要求

首先，我们需要安装`pigpio`包。在终端中，键入以下内容：

```js
**wget abyz.co.uk/rpi/pigpio/pigpio.zip**

```

然后解压包：

```js
**unzip pigpio.zip**

```

之后，使用以下内容导航到解压后的文件夹：

```js
**cd PIGPIO**

```

键入以下内容执行命令：

```js
**Make**

```

最后安装文件：

```js
**sudo make install**

```

## 测试 LED

在本节中，我们将使用**Node.js**脚本测试传感器：

```js
var Gpio = require('pigpio').Gpio; 

// Create led instance 
var led = new Gpio(18, {mode: Gpio.OUTPUT}); 
var dutyCycle = 0; 
// Go from 0 to maximum brightness 
setInterval(function () { 
  led.pwmWrite(dutyCycle); 
  dutyCycle += 5; 
  if (dutyCycle > 255) { 
    dutyCycle = 0; 
  } 
}, 20); 

```

我们现在可以测试这段代码，使用 Pi 上的终端导航到此项目的文件夹，并键入以下内容：

```js
**sudo npm install pigpio**

```

这将安装所需的`node.js`模块来控制 LED。然后，键入以下内容：

```js
**sudo node led_test.js**

```

这是最终结果：

![测试 LED](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_24.jpg)

## 从界面控制 LED

在本节中，我们将从网页控制 LED。为此，我们将使用 HTML 与用户进行界面交互，使用`node.js`。

让我们看一下以下代码中包含的 Node.js 文件：

```js
// Modules 
var Gpio = require('pigpio').Gpio; 
var express = require('express'); 
// Express app 
var app = express(); 

// Use public directory 
app.use(express.static('public')); 
// Create led instance 
var led = new Gpio(18, {mode: Gpio.OUTPUT}); 

// Routes 
app.get('/', function (req, res) { 

  res.sendfile(__dirname + '/public/interface.html'); 

}); 
app.get('/set', function (req, res) { 

  // Set LED 
  dutyCycle = req.query.dutyCycle; 
  led.pwmWrite(dutyCycle); 

  // Answer 
  answer = { 
    dutyCycle: dutyCycle 
  }; 
  res.json(answer); 

}); 

// Start server 
app.listen(3000, function () { 
  console.log('Raspberry Pi Zero LED control'); 
}); 

```

现在终于是时候测试我们的应用程序了！首先，从本书的存储库中获取所有代码，并像以前一样导航到项目的文件夹。然后，使用以下命令安装`express`：

```js
**sudo npm install express**

```

完成后，使用以下命令启动服务器：

```js
**sudo node led_control.js**

```

您现在可以测试项目，打开计算机上的网络浏览器，并输入链接- `http://（树莓派 PI）/set?dutyCycle=20`，我们可以看到 LED 随数值变化。

然后用`http://192.168.1.108:3000`打开您的网络浏览器，您应该在一个基本的网页上看到控制：

![从界面控制 LED](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_25.jpg)

# 控制直流电机的速度

在房子里通常会有窗户或车库门。我们需要自动化这些类型的设备，以便我们可以使用直流电机移动这些物体。在本节中，我们将看到如何将直流电机连接到树莓派。为此，我们将使用 L293D 电路来控制电机。

首先，我们将看到如何将电机连接到我们的树莓派 Zero 板上。在下图中，我们可以看到 LD293 芯片的引脚：

![控制直流电机的速度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_26.jpg)

基本上，我们需要连接电路的组件，如下所示：

+   树莓派的**GPIO14**连接到引脚**1A**

+   树莓派的**GPIO15**连接到引脚**2A**

+   树莓派的**GPIO18**连接到引脚**1**，**2EN**

+   **DC**电机连接到引脚**1Y**和**2Y**

+   树莓派的**5V**连接到**VCC1**

+   树莓派的**GND**连接到**GND**

+   适配器调节器连接到**VCC2**和**GND**

以下图显示了结果：

![控制直流电机的速度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_27.jpg)

我们现在将测试直流电机的速度从 0 到最高速度：

```js
// Modules 
var Gpio = require('pigpio').Gpio; 
// Create motor instance 
var motorSpeed = new Gpio(18, {mode: Gpio.OUTPUT}); 
var motorDirectionOne = new Gpio(14, {mode: Gpio.OUTPUT}); 
var motorDirectionTwo = new Gpio(15, {mode: Gpio.OUTPUT}) 

// Init motor direction 
motorDirectionOne.digitalWrite(0); 
motorDirectionTwo.digitalWrite(1); 
var dutyCycle = 0; 

// Go from 0 to maximum brightness 
setInterval(function () { 
  motorSpeed.pwmWrite(dutyCycle); 
  dutyCycle += 5; 
  if (dutyCycle > 255) { 
    dutyCycle = 0; 
  } 
}, 20); 

```

在这里，我们有这个应用程序的代码，可以使用网页界面来控制直流电机：

```js
// Modules 
var Gpio = require('pigpio').Gpio; 
var express = require('express'); 

// Express app 
var app = express(); 
// Use public directory 
app.use(express.static('public')); 

// Create led instance 
var motorSpeed = new Gpio(18, {mode: Gpio.OUTPUT}); 
var motorDirectionOne = new Gpio(14, {mode: Gpio.OUTPUT}); 
var motorDirectionTwo = new Gpio(15, {mode: Gpio.OUTPUT}); 

// Routes 
app.get('/', function (req, res) { 

  res.sendfile(__dirname + '/public/interface.html'); 

}); 

app.get('/set', function (req, res) { 
  // Set motor speed 
  speed = req.query.speed; 
  motorSpeed.pwmWrite(speed); 

  // Set motor direction 
  motorDirectionOne.digitalWrite(0); 
  motorDirectionTwo.digitalWrite(1); 

// Answer 
  answer = { 
    speed: speed 
  }; 
  res.json(answer); 

}); 

// Start server 
app.listen(3000, function () { 
  console.log('Raspberry Pi Zero Motor control started!'); 
}); 

```

我们在以下代码中看到用户界面：

```js
$( document ).ready(function() { 

  $( "#motor-speed" ).mouseup(function() { 

    // Get value 
    var speed = $('#motor-speed').val(); 

    // Set new value 
    $.get('/set?speed=' + speed); 

  }); 

}); 

<!DOCTYPE html> 
<html> 

<head> 
  <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script> 
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css"> 
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script> 
  <script src="js/interface.js"></script> 
  <link rel="stylesheet" href="css/style.css"> 
  <meta name="viewport" content="width=device-width, initial-scale=1"> 
</head> 
<body> 

<div id="container"> 

  <h3>Motor Control</h3> 

  <div class='row'> 

    <div class='col-md-4'></div> 
    <div class='col-md-4 text-center'> 
     <input id="motor-speed" type="range" value="0" min="0" max="255" step="1"> 
    </div> 
    <div class='col-md-4'></div> 

  </div> 

</div> 

</body> 
</html> 

```

要测试应用程序，您需要在计算机上打开网络浏览器，链接为`http://192.168.1.108:3000`，然后您需要替换您的 Pi 的 IP 地址。这是我们的界面：

![控制直流电机的速度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_28.jpg)

# 使用电气电路控制灯

在接下来的章节中，您将找到更多控制房屋其他设备的项目想法。

## 电器设备

在房子里，我们有电器设备，例如灯，洗衣机，加热器和其他我们只需要打开或关闭的设备。在本节中，我们将学习如何使用电气电路来控制连接到树莓派 Zero 的灯，以及如何使用光耦合器（如 MOC3011）和三角形。以下图显示了应用程序的电路：

![电器设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_29.jpg)

这里我们有连接到 Raspberry Pi Zero 的最终项目：

![电器设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_30.jpg)

这里有用于控制设备的 JavaScript 代码：

```js
// Modules 
var express = require('express'); 

// Express app 
var app = express(); 

// Pin 
var lampPin = 12; 

// Use public directory 
app.use(express.static('public')); 

// Routes 
app.get('/', function (req, res) { 

  res.sendfile(__dirname + '/public/interface.html'); 

}); 

app.get('/on', function (req, res) { 

  piREST.digitalWrite(lampPin, 1); 

  // Answer 
  answer = { 
    status: 1 
  }; 
  res.json(answer); 

}); 

app.get('/off', function (req, res) { 

  piREST.digitalWrite(lampPin, 0); 

  // Answer 
  answer = { 
    status: 0 
  }; 
  res.json(answer); 

}); 

// aREST 
var piREST = require('pi-arest')(app); 
piREST.set_id('34f5eQ'); 
piREST.set_name('my_rpi_zero'); 

// Start server 
app.listen(3000, function () { 
  console.log('Raspberry Pi Zero lamp control started!'); 
}); 

```

我们需要一个可以通过 HTML 语言的网页控制灯的界面：

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

<body> 

<div id="container"> 

  <h3>Lamp Control</h3> 

  <div class='row'> 

    <div class='col-md-4'></div> 
    <div class='col-md-2'> 
      <button id='on' class='btn btn-block btn-primary'>On</button> 
    </div> 
    <div class='col-md-2'> 
      <button id='off' class='btn btn-block btn-warning'>Off</button> 
    </div> 
    <div class='col-md-4'></div> 

  </div> 

</div> 

</body> 
</html> 

```

进入网络浏览器后，我们将看到以下界面：

![电器设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_31.jpg)

# 其他家用电器

在这一部分，我们将展示其他应用程序，您可以考虑创建和控制，然后在家里或不同的区域使用它们。

## 控制门锁

在这一部分，我们将看到其他可以从界面控制并连接到 Raspberry Pi 的家用电器。在家里，我们可以通过 Web 界面控制门锁：

![控制门锁](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_32.jpg)

## 控制浇水设备

我们可以控制的另一个家用电器是连接到 Raspberry Pi 的塑料水电磁阀-12V 的浇水设备：

![控制浇水设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_33.jpg)

通过这个项目，我们可以制作一个自动浇水系统，添加一个湿度传感器，并设置花园植物的浇水时间。

# 从任何地方远程访问您的 Raspberry Pi Zero

如果我们想要从网络外部访问我们的 Raspberry Pi，我们需要执行以下操作：

+   检查我们的调制解调器是否有公共 IP 地址

+   调查我们将在浏览器中使用的地址

+   在我们的浏览器中输入[`whatismyipaddress.com/`](http://whatismyipaddress.com/)![从任何地方远程访问您的 Raspberry Pi Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_34.jpg)

ISP 提供的 IP 通常是动态 IP，会随时间变化。在我们的情况下，我们需要具有不时更改的静态地址。

## 如何访问我们的调制解调器进行配置

通过 IP 地址（网关）访问我们的调制解调器，并转到端口寻址部分。配置指向我们的 Web 服务器的端口*80*（输入我们帐户的 IP 地址），此 IP 地址是我们系统的 DHCP 服务器自动分配的 IP 地址。

这里有一些可以从调制解调器-路由器转发的端口：

![如何访问我们的调制解调器进行配置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_35.jpg)

要获取网关 IP 地址，请输入`ipconfig`命令，您需要具有管理员权限。之后，在您的`router.1`的网络浏览器中输入`http://gatewayip_addres`：

![如何访问我们的调制解调器进行配置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_36.jpg)

这是您在 Linksys 路由器上看到的示例，您的界面可能不同：

![如何访问我们的调制解调器进行配置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_37.jpg)

要打开一个端口，我们需要配置我们的路由器以允许从外部进入，因此我们需要在我们的路由器中给予权限：

![如何访问我们的调制解调器进行配置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_38.jpg)

这个屏幕截图显示了最终结果，如何打开端口号 3000，以及应用程序节点的名称：

![如何访问我们的调制解调器进行配置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_39_Updated.jpg)

## 配置动态 DNS

我们需要配置域名服务，这样我们就可以通过输入我们域名的名称来访问我们的 Web 服务器（学习网页的 IP 地址非常困难）。这就是为什么创建了**域名服务器（DNS)**。请按照下一节创建域名。

您可能希望从家外访问您的物联网控制面板。在这种情况下，您的 Web 服务器将需要成为互联网上的主机。

这并不是一件简单的事情，因为它在您家中的路由器后面。您的 ISP 通常不会给您一个静态的公共 IP 地址，因为大多数用户只是访问网络，而不是提供网页服务。

因此，您的路由器的公共一侧会被分配一个可能会不时更改的 IP 地址。如果您浏览`<whatsmyip...>`，您将看到您当前的公共 IP 是什么。

明天可能会不同。要设置外部访问，您可以选择以下两种方法之一。如果您想模拟具有静态 IP，可以使用动态 DNS 等服务。如果您只是想“尝试”外部访问，可以在路由器上打开一个端口

动态 DNS 的好处：

+   一种解决方案是安装一个客户端，允许公共 IP 固定。客户端功能（安装在计算机上的软件）与网站[www.no-ip.org](http://www.no-ip.com)保持通信。

+   当我们的调制解调器的 IP 地址发生变化时，客户端会接受该 IP 变化。

+   这样我们的域名就可以始终指向我们的公共 IP 地址。安装的软件称为：No-IP DUC。

## 在 No-ip.org 创建一个账户

在下面的截图中，我们可以看到增强动态 DNS 设置：

![在 No-ip.org 创建一个账户](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_40.jpg)

# 控制灯光和测量电流消耗

现在，在本节中，我们将解释如何在灯开启或关闭时控制和监控您的电流消耗。通过 Web 页面使用您的 Arduino Wi-Fi shield，我们将监控此变量。当灯关闭时，它看起来如下：

![控制灯光和测量电流消耗](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_41.jpg)

当灯开启时，它看起来如下：

![控制灯光和测量电流消耗](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_42.jpg)

现在，您可以将代码复制到名为`Controlling_lights_Current_Consumption.ino`的文件中，或者只需从本书的文件夹中获取完整的代码。

定义监控和控制的变量和函数：

```js
#define NUMBER_VARIABLES 2 
#define NUMBER_FUNCTIONS 1 

```

导入库以使用：

```js
#include <Adafruit_CC3000.h> 
#include <SPI.h> 
#include <CC3000_MDNS.h> 
#include <aREST.h> 

```

配置继电器以激活：

```js
const int relay_pin = 8; 

```

计算电流的变量：

```js
float amplitude_current; 
float effective_value; 
float effective_voltage = 110; 
float effective_power; 
float zero_sensor; 

```

我们定义用于配置模块的引脚：

```js
#define ADAFRUIT_CC3000_IRQ   3 
#define ADAFRUIT_CC3000_VBAT  5 
#define ADAFRUIT_CC3000_CS    10 
Adafruit_CC3000 cc3000 = Adafruit_CC3000(ADAFRUIT_CC3000_CS,  
ADAFRUIT_CC3000_IRQ, ADAFRUIT_CC3000_VBAT); 

```

我们创建实例：

```js
aREST rest = aREST(); 

```

我们定义您网络的 SSID 和密码：

```js
#define WLAN_SSID       "xxxxxxxx" 
#define WLAN_PASS       "xxxxxxxx" 
#define WLAN_SECURITY   WLAN_SEC_WPA2 

```

我们配置服务器的端口：

```js
#define LISTEN_PORT 80 

```

服务器的实例：

```js
Adafruit_CC3000_Server restServer(LISTEN_PORT); 
MDNSResponder mdns; 

```

使用的变量：

```js
int power; 
int light; 

```

发布使用的变量：

```js
void setup(void) 
{   
  Serial.begin(115200); 
  rest.variable("light",&light); 
  rest.variable("power",&power); 

```

设置继电器引脚为输出：

```js
pinMode(relay_pin,OUTPUT); 

```

校准电流传感器：

```js
  zero_sensor = getSensorValue(A1); 

```

我们声明设备的 id 和名称：

```js
  rest.set_id("001"); 
  rest.set_name("control"); 

```

在这部分，我们检查设备是否已连接：

```js
  if (!cc3000.begin()) 
  { 
    while(1); 
  } 

  if (!cc3000.connectToAP(WLAN_SSID, WLAN_PASS, WLAN_SECURITY)) { 
    while(1); 
  } 
  while (!cc3000.checkDHCP()) 
  { 
    delay(100); 
  } 

```

在这部分中，我们定义了通信请求：

```js
  if (!mdns.begin("arduino", cc3000)) { 
    while(1);  
  } 
  displayConnectionDetails(); 

```

让我们启动服务器：

```js
  restServer.begin(); 
  Serial.println(F("Listening for connections...")); 
} 

```

我们读取传感器：

```js
void loop() { 

  float sensor_reading = analogRead(A0); 
  light = (int)(sensor_reading/1024*100); 
  float sensor_value = getSensorValue(A1); 

```

我们进行电流计算并获取信号：

```js
  amplitude_current = (float)(sensor_value-zero_sensor)/1024*5/185*1000000; 
  effective_value = amplitude_current/1.414; 
  effective_power = abs(effective_value*effective_voltage/1000); 
  power = (int)effective_power; 
  mdns.update(); 

```

我们定义传入请求：

```js
Adafruit_CC3000_ClientRef client = restServer.available(); 
  rest.handle(client); 
 } 

```

我们显示 IP 地址配置：

```js
bool displayConnectionDetails(void) 
{ 
  uint32_t ipAddress, netmask, gateway, dhcpserv, dnsserv; 

  if(!cc3000.getIPAddress(&ipAddress, &netmask, &gateway, &dhcpserv, &dnsserv)) 
  { 
    Serial.println(F("Unable to retrieve the IP Address!\r\n")); 
    return false; 
  } 
  else 
  { 
    Serial.print(F("\nIP Addr: ")); cc3000.printIPdotsRev(ipAddress); 
    Serial.print(F("\nNetmask: ")); cc3000.printIPdotsRev(netmask); 
    Serial.print(F("\nGateway: ")); cc3000.printIPdotsRev(gateway); 
    Serial.print(F("\nDHCPsrv: ")); cc3000.printIPdotsRev(dhcpserv); 
    Serial.print(F("\nDNSserv: ")); cc3000.printIPdotsRev(dnsserv); 
    Serial.println(); 
    return true; 
  } 
} 

```

电流传感器的功能，计算特定测量的平均值并返回电流计算：

```js
float getSensorValue(int pin) 
{ 
  int sensorValue; 
  float avgSensor = 0; 
  int nb_measurements = 100; 
  for (int i = 0; i < nb_measurements; i++) { 
    sensorValue = analogRead(pin); 
    avgSensor = avgSensor + float(sensorValue); 
  }      
  avgSensor = avgSensor/float(nb_measurements); 
  return avgSensor; 
} 

```

## 构建控制和监控界面

这里有用于显示控制灯光和监控传感器电流的界面的代码：

### 为 Node.js 安装 Jade

在这个项目中使用 Jade 界面很重要。为此，我们只需输入以下命令：

```js
**npm install arest express jade** 

```

如果需要，我们可以在系统需要更新时输入以下命令：

```js
**npm install pug**

```

## 用于控制和监控的界面

首先，我们定义页面的标题并添加 HTML 标签：

```js
doctype 
html 
  head 
    title Control and monitoring 

```

我们为 jQuery 和 Bootstrap 的功能定义链接：

```js
link(rel='stylesheet', href='/css/interface.css') 
    link(rel='stylesheet',  
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.0/css/bootstrap.min.css") 
    script(src="https://code.jquery.com/jquery-2.1.1.min.js") 
    script(src="/js/interface.js") 

```

我们在网页上显示控制按钮：

```js
  body 
    .container 
      h1 Controlling lights 
      .row.voffset 
        .col-md-6 
          button.btn.btn-block.btn-lg.btn-primary#1 On 
        .col-md-6 
          button.btn.btn-block.btn-lg.btn-danger#2 Off 
      .row 

```

显示功率和光照水平：

```js
        .col-md-4 
          h3#powerDisplay Power: 
        .col-md-4 
          h3#lightDisplay Light level:  
        .col-md-4 
          h3#status Offline 

```

现在我们将运行应用程序，如下截图所示。服务器在端口 3000 上打开，当它开始向板发送请求时，在 Web 浏览器中键入地址：`http://localhost:3000`。它显示了带有两个按钮的网页，设备已连接并在线：

![用于控制和监控的界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_43.jpg)

单击蓝色**开**按钮以激活板上的灯，几秒钟后我们可以看到功率增加：

![用于控制和监控的界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_44.jpg)

单击红色**关**按钮，几秒钟后功率下降直到*0 W*，这意味着一切都运行正常：

![用于控制和监控的界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_45.jpg)

# 在连接设备和传感器上控制和监控 Arduino、Wi-Fi 和以太网 shield

在前几节中，我们看到如何使用在 Windows 计算机上运行的`node.js`从网页控制和监视我们的 Arduino 板。在本节中，我们将使用我们神奇的树莓派 Zero，在其上安装了 Node.js，并在板上运行 JavaScript 应用程序。

我已经看到了使用树莓派 Zero 而不是使用个人计算机安装为 Web 服务器的潜力，通过这种经验制作这些项目，我想说应用程序在树莓派 Zero 上运行更有效。

我们将看到如何在单个仪表板中使用不同设备控制多个设备，例如以下设备：

+   Wi-Fi 盾

+   ESP8266 模块

+   以太网盾

## 构建控制和监视设备的代码，从单一界面进行监控

现在您可以将代码复制到名为`app.js`的文件中，或者只需从此项目的文件夹中获取完整的代码。

配置系统中连接的设备的输出：

```js
$.getq('queue', '/lamp_control/mode/8/o'); 
$.getq('queue', '/lamp_control2/mode/5/o'); 

```

启动控制功能：

```js
$(document).ready(function() { 

```

我们使用`aREST` API 进行`ON`的`GET`请求：

```js
// Function to control lamp Ethernet Shield 
  $("#1").click(function() { 
    $.getq('queue', '/lamp_control/digital/8/1'); 
  }); 

```

我们使用`ARESt` API 进行`OFF`的`GET`请求：

```js
  $("#2").click(function() { 
    $.getq('queue', '/lamp_control/digital/8/0'); 
  }); 

```

我们对连接的 ESP8266 设备进行相同的操作`ON`：

```js
//Function to control lamp ESP8266 
  $("#3").click(function() { 
    $.getq('queue', '/lamp_control2/digital/5/0'); 
  }); 

```

我们对连接的 ESP8266 设备进行相同的操作`OFF`：

```js
$("#4").click(function() { 
    $.getq('queue', '/lamp_control2/digital/5/1'); 
  }); 

```

从传感器温度和湿度获取数据：

```js
  function refresh_dht() { 
        $.getq('queue', '/sensor/temperature', function(data) { 
      $('#temperature').html("Temperature: " + data.temperature + " C"); 
    }); 

  $.getq('queue', '/sensor2/temperature2', function(data) { 
      $('#temperature2').html("Temperature: " + data.temperature2 + " C"); 
    }); 

  $.getq('queue', '/sensor/humidity', function(data) { 
      $('#humidity').html("Humidity: " + data.humidity + " %"); 
    }); 
         $.getq('queue', '/sensor2/humidity2', function(data) { 
      $('#humidity2').html("Humidity: " + data.humidity2 + " %"); 
}); 
  } 

```

此代码每 10000 秒刷新页面一次：

```js
refresh_dht(); 
setInterval(refresh_dht, 10000); 
}); 

```

## 添加要监视和控制的设备

我可以看到系统非常稳定；我们需要添加将从树莓派 Zero 监视的设备，使用以下 JavaScript 片段中的应用程序。

我们创建 express 模块和必要的库：

```js
var express = require('express'); 
var app = express(); 

```

我们定义将要打开的端口：

```js
var port = 3000; 

```

我们为 HTML 网页配置 Jade 引擎：

```js
app.set('view engine', 'jade'); 

```

我们创建公共目录以便访问：

```js
app.use(express.static(__dirname + '/public')); 

```

执行服务器指令的界面：

```js
app.get('/', function(req, res){ 
res.render('interface'); 
}); 

```

我们使用 rest 请求声明逮捕文件：

```js
var rest = require("arest")(app); 

```

此代码定义将被控制和监视的设备，我们可以添加想要的设备：

```js
rest.addDevice('http','192.168.1.108'); 
rest.addDevice('http','192.168.1.105'); 
rest.addDevice('http','192.168.1.107'); 
rest.addDevice('http','192.168.1.110'); 

```

我们在端口 3000 上设置服务器并监听 Web 浏览器客户端：

```js
app.listen(port); 
console.log("Listening on port " + port); 

```

如果一切都配置完美，我们通过输入以下命令来测试应用程序：

```js
**sudo npm install arest express jade**

```

这将安装 Jade 平台并识别来自树莓派 Zero 的`aREST` API。

如果需要更新某些内容，请输入以下命令：

```js
**sudo npm install pug**

```

要更新`arrest express`，请输入以下命令：

```js
**sudo npm install pi-arest express** 

```

安装此软件包非常重要，以包括逮捕 API：

```js
**sudo npm install arest --unsafe-perm**

```

要运行应用程序，请转到应用程序所在的文件夹，并输入以下命令：

```js
**node app.js**

```

在下面的屏幕截图中，我们看到服务器正在打开端口 3000：

![添加要监视和控制的设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_46.jpg)

最后的测试中，我们需要在您喜欢的网络浏览器中输入树莓派此刻的 IP 地址：`http://IP_Address_of_Raspberry_Pi_Zero/port`。

在下面的屏幕截图中，我们可以看到来自树莓派 Zero 的控制和监视数据仪表板，发布在单个网页上的不同设备上，这是一件有趣的事情，可以远程系统和控制面板：

![添加要监视和控制的设备](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_06_47.jpg)

最后，我们通过在单个数据仪表板中使用不同设备来展示控制和监视系统；我们得出结论，物联网可以在一个网页中拥有多个设备。

# 总结

在本章中，您学习了如何使用树莓派 Zero 与 Arduino 和之前章节中介绍的技术集成和构建监控仪表板。本章为您提供了基础知识和必要工具，可以帮助您创建自己的物联网系统，用于不同应用和领域，通过应用所有工具、Web 服务器、数据库服务器、连接的设备，并设置路由器来控制您的树莓派，从世界各地的任何地方。

在下一章中，您将为物联网构建非常好的设备；您将学习如何制作不同的迷你家庭自动化项目。
