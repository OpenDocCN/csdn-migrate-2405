# JavaScript 物联网实战（三）

> 原文：[`zh.annas-archive.org/md5/8F10460F1A267E7E0720699DAEDCAC44`](https://zh.annas-archive.org/md5/8F10460F1A267E7E0720699DAEDCAC44)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：智能可穿戴设备

在本章中，我们将介绍如何使用树莓派 3 创建一个简单的医疗保健应用程序。我们将构建一个带有 16x2 液晶显示屏的智能可穿戴设备，显示用户的位置，并在 Web/桌面/移动界面上显示加速度计的数值。这个产品的目标用户主要是年长者，主要用例是跌倒检测，我们将在第七章中进行讨论，*智能可穿戴设备和 IFTTT*。

在本章中，我们将讨论以下内容：

+   物联网和医疗保健

+   设置所需的硬件

+   整合加速度计并查看实时数据

# 物联网和医疗保健

想象一位成功接受心脏移植手术并在医院术后护理后被送回家的患者。对这位患者的关注程度将显著降低，因为家庭设施与医院相比将是最低的。这就是物联网以其实时能力介入的地方。

物联网和医疗保健是天作之合。风险和回报同样巨大。能够实时监测患者的健康状况，并获取他们的脉搏、体温和其他重要统计数据的信息，并对其进行诊断和处理是非常宝贵的。与此同时，如果连接中断两分钟，就会有人的生命受到威胁。

在我看来，要实现物联网在医疗保健领域的全部潜力，我们可能需要再等待 5-10 年，那时的连接将是绝对无缝的，数据包丢失将成为历史。

# 智能可穿戴设备

如前一节所述，我们将使用物联网在医疗保健领域做一些关键的事情。我们要构建的智能可穿戴设备的主要目的是识别跌倒。一旦识别到跌倒，我们就会通知云端。当我们周围有年长或患病的人因意外原因而倒下时，及时识别跌倒并采取行动有时可以挽救生命。

为了检测跌倒，我们将使用加速度计。引用维基百科的话：

"**加速度计**是一种测量真实加速度的设备。真实加速度是指物体在其瞬时静止参考系中的加速度（或速度变化率），并不同于坐标加速度，即在固定坐标系中的加速度。例如，静止在地球表面的加速度计将测量由于地球重力而产生的加速度，垂直向上（根据定义）为 g ≈ 9.81 m/s2。相比之下，自由下落的加速度计（以约 9.81 m/s2 的速率朝向地球中心下落）将测量为零。"

要了解更多关于加速度计及其工作原理的信息，请参阅*加速度计的工作原理*：[`www.youtube.com/watch?v=i2U49usFo10`](https://www.youtube.com/watch?v=i2U49usFo10)。

在本章中，我们将实现基本系统，收集 X、Y 和 Z 轴加速度原始值，并在 Web、桌面和移动应用程序上显示。在第七章中，*智能可穿戴设备和 IFTTT*，我们将使用这些数值来实现跌倒检测。

除了实时收集加速度计数值外，我们还将使用 16x2 液晶显示屏显示当前时间和用户的地理位置。如果需要，我们也可以在显示屏上添加其他文本。16x2 是一个简单的界面来显示内容。这可以通过诺基亚 5110 液晶屏（[`www.amazon.in/inch-Nokia-5110-KG075-KitsGuru/dp/B01CXNSJOA`](http://www.amazon.in/inch-Nokia-5110-KG075-KitsGuru/dp/B01CXNSJOA)）进行扩展，以获得具有图形的更高级显示。

在接下来的部分，我们将组装所需的硬件，然后更新树莓派代码。之后，我们将开始处理 API 引擎和 UI 模板。

# 设置智能可穿戴设备

关于硬件设置的第一件事是它又大又笨重。这只是一个 POC，甚至不是一个接近生产设置的远程。硬件设置将包括连接到树莓派 3 和 16X2 LCD 的加速度计。

加速度计 ADXL345 通过 I2C 协议提供 X、Y 和 Z 轴的加速度。

按照以下方式连接硬件：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00093.jpeg)

正如您在上面的原理图中所看到的，我们已经建立了以下连接：

+   树莓派和 LCD：

| **树莓派编号 - 引脚名称** | **16x2 LCD Pi 名称** |
| --- | --- |
| 6 - GND - 面包板导轨 1 | 1 - GND |
| 2 - 5V - 面包板导轨 2 | 2 - VCC |
| 1 k Ohm 电位计 | 3 - VEE |
| 32 - GPIO 12 | 4 - RS |
| 6 - GND - 面包板导轨 1 | 5 -R/W |
| 40 - GPIO 21 | 6 - EN |
| NC | 7 - DB0 |
| NC | 8 - DB1 |
| NC | 9 - DB2 |
| NC | 10 - DB3 |
| 29 - GPIO 5 | 11 - DB4 |
| 31 - GPIO 6 | 12 - DB5 |
| 11 - GPIO 17 | 13 - DB6 |
| 12 - GPIO 18 | 14 - DB7 |
| 2 - 5V - 面包板导轨 2 | 15 - LED+ |
| 6 - GND - 面包板导轨 1 | 16 - LED- |

+   树莓派和 ADXL345：

| **树莓派编号 - 引脚名称** | **ADXL345 引脚编号 - 引脚名称** |
| --- | --- |
| 1 - 3.3V | VCC |
| 6 - GND - 面包板导轨 1 | GND |
| 5 - GPIO3/SCL1 | SCL |
| 3 - GPIO2/SDA1 | SDA |
| 6 - GND - 面包板导轨 1 | SDO |

我们将添加所需的代码：

1.  首先创建一个名为`chapter6`的文件夹，然后将`chapter4`的内容复制到其中。我们将随着进展更新此代码

1.  现在，我们将开始使用`pi-client`。在树莓派上，打开`pi-client/index.js`并按照以下方式更新它：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt'); 
var GetMac = require('getmac'); 
var request = require('request'); 
var ADXL345 = require('adxl345-sensor'); 
require('events').EventEmitter.prototype._maxListeners = 100; 

var adxl345 = new ADXL345(); // defaults to i2cBusNo 1, i2cAddress 0x53 

var Lcd = require('lcd'), 
    lcd = new Lcd({ 
        rs: 12, 
        e: 21, 
        data: [5, 6, 17, 18], 
        cols: 8, 
        rows: 2 
    }); 

var aclCtr = 0, 
    locCtr = 0; 

var x, prevX, y, prevY, z, prevZ; 
var locationG; // global location variable 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('rpi'); 
    client.subscribe('socket'); 
    GetMac.getMac(function(err, mac) { 
        if (err) throw err; 
        macAddress = mac; 
        displayLocation(); 
        initADXL345(); 
        client.publish('api-engine', mac); 
    }); 
}); 

client.on('message', function(topic, message) { 
    message = message.toString(); 
    if (topic === 'rpi') { 
        console.log('API Engine Response >> ', message); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 

function initADXL345() { 
    adxl345.init().then(function() { 
            console.log('ADXL345 initialization succeeded'); 
            // init loop after ADXL345 has been setup 
            loop(); 
        }) 
        .catch(function(err) { 
            console.error('ADXL345 initialization failed: ', err); 
        }); 
} 

function loop() { 
    // infinite loop, with 1 seconds delay 
    setInterval(function() { 
        // wait till we get the location 
        // then start processing 
        if (!locationG) return; 

        if (aclCtr === 3) { // every 3 seconds 
            aclCtr = 0; 
            readSensorValues(function(acclVals) { 
                var x = acclVals.x; 
                var y = acclVals.y; 
                var z = acclVals.z; 

                var data2Send = { 
                    data: { 
                        acclVals: acclVals, 
                        location: locationG 
                    }, 
                    macAddress: macAddress 
                }; 

                // no duplicate data 
                if (x !== prevX || y !== prevY || z !== prevZ) { 
                    console.log('data2Send', data2Send); 
                    client.publish('accelerometer', JSON.stringify(data2Send)); 
                    console.log('Data Published'); 
                    prevX = x; 
                    prevY = y; 
                    prevZ = z; 
                } 
            }); 
        } 

        if (locCtr === 300) { // every 300 seconds 
            locCtr = 0; 
            displayLocation(); 
        } 

        aclCtr++; 
        locCtr++; 
    }, 1000); // every one second 
} 

function readSensorValues(CB) { 
    adxl345.getAcceleration(true) // true for g-force units, else false for m/s² 
        .then(function(acceleration) { 
            if (CB) CB(acceleration); 
        }) 
        .catch((err) => { 
            console.log('ADXL345 read error: ', err); 
        }); 
} 

function displayLocation() { 
    request('http://ipinfo.io', function(error, res, body) { 
        var info = JSON.parse(body); 
        // console.log(info); 
        locationG = info; 
        var text2Print = ''; 
        text2Print += 'City: ' + info.city; 
        text2Print += ' Region: ' + info.region; 
        text2Print += ' Country: ' + info.country + ' '; 
        lcd.setCursor(16, 0); // 1st row     
        lcd.autoscroll(); 
        printScroll(text2Print); 
    }); 
} 

// a function to print scroll 
function printScroll(str, pos) { 
    pos = pos || 0; 

    if (pos === str.length) { 
        pos = 0; 
    } 

    lcd.print(str[pos]); 
    //console.log('printing', str[pos]); 

    setTimeout(function() { 
        return printScroll(str, pos + 1); 
    }, 300); 
} 

// If ctrl+c is hit, free resources and exit. 
process.on('SIGINT', function() { 
    lcd.clear(); 
    lcd.close(); 
    process.exit(); 
}); 
```

从上述代码中可以看出，我们使用`displayLocation()`每小时显示一次位置，因为我们假设位置不会经常改变。我们使用[`ipinfo.io/`](http://ipinfo.io/)服务来获取用户的位置。

1.  最后，使用`readSensorValues()`我们每`3`秒获取一次`加速度计`的值，并将这些数据发布到名为`accelerometer`的主题中。

1.  现在，我们将安装所需的依赖项。从`pi-client`文件夹内部运行以下命令：

```js
npm install async getmac adxl345-sensor mqtt request --save
```

1.  保存所有文件并通过运行在服务器或我们的桌面机器上启动 mosca broker 来启动：

```js
mosca -c index.js -v | pino  
```

1.  接下来，在树莓派上运行代码：

```js
npm start  
```

这将启动`pi-client`并开始收集加速度计数据，并在 LCD 显示器上显示位置如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00094.jpeg)

我的设置如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00095.jpeg)

接下来，我们将与 API 引擎一起工作。

# 更新 API 引擎

现在我们已经让智能可穿戴设备运行并发送了三轴数据，我们现在将实现 API 引擎中接受该数据所需的逻辑，并将数据发送到 Web/桌面/移动应用程序中：

打开`api-engine/server/mqtt/index.js`并按照以下方式更新它：

```js
var Data = require('../api/data/data.model'); 
var mqtt = require('mqtt'); 
var config = require('../config/environment'); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    console.log('Connected to Mosca at ' + config.mqtt.host + ' on port ' + config.mqtt.port); 
    client.subscribe('api-engine'); 
    client.subscribe('accelerometer'); 
}); 

client.on('message', function(topic, message) { 
    // message is Buffer 
    // console.log('Topic >> ', topic); 
    // console.log('Message >> ', message.toString()); 
    if (topic === 'api-engine') { 
        var macAddress = message.toString(); 
        console.log('Mac Address >> ', macAddress); 
        client.publish('rpi', 'Got Mac Address: ' + macAddress); 
    } else if (topic === 'accelerometer') { 
        var data = JSON.parse(message.toString()); 
        // create a new data record for the device   
        Data.create(data, function(err, data) { 
            if (err) return console.error(err); 
            // if the record has been saved successfully,  
            // websockets will trigger a message to the web-app 
            console.log('Data Saved :', data.data); 
        }); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 
```

在这里，我们订阅名为`accelerometer`的主题，并监听其变化。接下来，我们将按照以下方式更新`api-engine/server/api/data/data.controller.js`：

```js
'use strict'; 

var Data = require('./data.model'); 

/** 
 * Get Data for a device 
 */ 
exports.index = function(req, res) { 
    var macAddress = req.params.deviceId; 
    var limit = parseInt(req.params.limit) || 30; 

    Data 
        .find({ 
            macAddress: macAddress 
        }) 
        .sort({ 'createdAt': -1 }) 
        .limit(limit) 
        .exec(function(err, data) { 
            if (err) return res.status(500).send(err); 
            res.status(200).json(data); 
        }); 
}; 

/** 
 * Create a new data record 
 */ 
exports.create = function(req, res, next) { 
    var data = req.body || {}; 
    data.createdBy = req.user._id; 

    Data.create(data, function(err, _data) { 
        if (err) return res.status(500).send(err); 
        return res.json(_data); 
    }); 
}; 
```

上述代码用于将数据保存到数据库，并在从 Web、桌面和移动应用程序请求时从数据库中获取数据。

保存所有文件并运行 API 引擎：

```js
npm start
```

这将启动 API 引擎，如果需要，我们可以重新启动智能可穿戴设备，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00096.jpeg)

在下一节中，我们将在 Web 应用程序中显示数据。

# 更新 Web 应用程序

现在我们已经完成了 API 引擎，我们将更新 Web 应用程序中的模板以显示三轴数据。打开`web-app/src/app/device/device.component.html`并按照以下方式更新它：

```js
<div class="container">
  <br>
  <div *ngIf="!device">
    <h3 class="text-center">Loading!</h3>
  </div>
  <div class="row" *ngIf="lastRecord">
    <div class="col-md-12">
      <div class="panel panel-info">
        <div class="panel-heading">
          <h3 class="panel-title">
                        {{device.name}}
                    </h3>
          <span class="pull-right btn-click">
                        <i class="fa fa-chevron-circle-up"></i>
                    </span>
        </div>
        <div class="clearfix"></div>
        <div class="table-responsive">
          <table class="table table-striped">
            <tr *ngIf="lastRecord">
              <td>X-Axis</td>
              <td>{{lastRecord.data.acclVals.x}} {{lastRecord.data.acclVals.units}}</td>
            </tr>
            <tr *ngIf="lastRecord">
              <td>Y-Axis</td>
              <td>{{lastRecord.data.acclVals.y}} {{lastRecord.data.acclVals.units}}</td>
            </tr>
            <tr *ngIf="lastRecord">
              <td>Z-Axis</td>
              <td>{{lastRecord.data.acclVals.z}} {{lastRecord.data.acclVals.units}}</td>
            </tr>
            <tr *ngIf="lastRecord">
              <td>Location</td>
              <td>{{lastRecord.data.location.city}}, {{lastRecord.data.location.region}}, {{lastRecord.data.location.country}}</td>
            </tr>
            <tr *ngIf="lastRecord">
              <td>Received At</td>
              <td>{{lastRecord.createdAt | date : 'medium'}}</td>
            </tr>
          </table>
          <hr>
          <div class="col-md-12" *ngIf="acclVals.length > 0">
            <canvas baseChart [datasets]="acclVals" [labels]="lineChartLabels" [options]="lineChartOptions" [legend]="lineChartLegend" [chartType]="lineChartType"></canvas>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
```

所需的逻辑将在`device.component.ts`中。打开`web-app/src/app/device/device.component.ts`并按照以下方式更新它：

```js
import { Component, OnInit, OnDestroy } from '@angular/core';
import { DevicesService } from '../services/devices.service';
import { Params, ActivatedRoute } from '@angular/router';
import { SocketService } from '../services/socket.service';
import { DataService } from '../services/data.service';
import { NotificationsService } from 'angular2-notifications';

@Component({
  selector: 'app-device',
  templateUrl: './device.component.html',
  styleUrls: ['./device.component.css']
})
export class DeviceComponent implements OnInit, OnDestroy {
  device: any;
  data: Array<any>;
  toggleState: boolean = false;
  private subDevice: any;
  private subData: any;
  lastRecord: any;

  // line chart config
  public lineChartOptions: any = {
    responsive: true,
    legend: {
      position: 'bottom',
    }, hover: {
      mode: 'label'
    }, scales: {
      xAxes: [{
        display: true,
        scaleLabel: {
          display: true,
          labelString: 'Time'
        }
      }],
      yAxes: [{
        display: true,
        ticks: {
          beginAtZero: true,
          // steps: 10,
          // stepValue: 5,
          // max: 70
        }
      }],
      zAxes: [{
        display: true,
        ticks: {
          beginAtZero: true,
          // steps: 10,
          // stepValue: 5,
          // max: 70
        }
      }]
    },
    title: {
      display: true,
      text: 'X,Y,Z vs. Time'
    }
  };

  public lineChartLegend: boolean = true;
  public lineChartType: string = 'line';
  public acclVals: Array<any> = [];
  public lineChartLabels: Array<any> = [];

  constructor(private deviceService: DevicesService,
    private socketService: SocketService,
    private dataService: DataService,
    private route: ActivatedRoute,
    private notificationsService: NotificationsService) { }

  ngOnInit() {
    this.subDevice = this.route.params.subscribe((params) => {
      this.deviceService.getOne(params['id']).subscribe((response) => {
        this.device = response.json();
        this.getData();
      });
    });
  }

  getData() {
    this.dataService.get(this.device.macAddress).subscribe((response) => {
      this.data = response.json();
      this.lastRecord = this.data[0]; // descending order data
      this.toggleState = this.lastRecord.data.s;
      this.genChart();
      this.socketInit();
    });
  }

  socketInit() {
    this.subData = this.socketService.getData(this.device.macAddress).subscribe((data) => {
      if (this.data.length <= 0) return;
      this.data.splice(this.data.length - 1, 1); // remove the last record
      this.data.push(data); // add the new one
      this.lastRecord = data;
      this.toggleState = this.lastRecord.data.s;
      this.genChart();
    });
  }

  ngOnDestroy() {
    this.subDevice.unsubscribe();
    this.subData ? this.subData.unsubscribe() : '';
  }

  genChart() {
    let data = this.data;
    let _acclVals: Array<any> = [];
    let _lblArr: Array<any> = [];

    let xArr: Array<any> = [];
    let yArr: Array<any> = [];
    let zArr: Array<any> = [];

    for (var i = 0; i < data.length; i++) {
      let _d = data[i];
      xArr.push(_d.data.acclVals.x);
      yArr.push(_d.data.acclVals.y);
      zArr.push(_d.data.acclVals.z);
      _lblArr.push(this.formatDate(_d.createdAt));
    }

    // reverse data to show the latest on the right side
    xArr.reverse();
    yArr.reverse();
    zArr.reverse();
    _lblArr.reverse();

    _acclVals = [
      {
        data: xArr,
        label: 'X-Axis'
      },
      {
        data: yArr,
        label: 'Y-Axis'
      },
      {
        data: zArr,
        label: 'Z-Axis'
      }
    ]

    this.acclVals = _acclVals;

    this.lineChartLabels = _lblArr;
  }

  private formatDate(originalTime) {
    var d = new Date(originalTime);
    var datestring = d.getDate() + "-" + (d.getMonth() + 1) + "-" + d.getFullYear() + " " +
      d.getHours() + ":" + d.getMinutes();
    return datestring;
  }

}
```

保存所有文件并运行以下命令：

```js
npm start  
```

导航到`http://localhost:4200`并查看设备，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00097.jpeg)

通过这样，我们已经完成了 Web 应用程序。

# 更新桌面应用程序

现在 Web 应用程序已经完成，我们将构建相同的应用程序并将其部署到我们的桌面应用程序中。

要开始，请返回到`web-app`文件夹的终端/提示符，并运行：

```js
ng build --env=prod
```

这将在`web-app`文件夹内创建一个名为`dist`的新文件夹。`dist`文件夹的内容应该类似于以下内容：

```js
.

├── favicon.ico

├── index.html

├── inline.bundle.js

├── inline.bundle.js.map

├── main.bundle.js

├── main.bundle.js.map

├── polyfills.bundle.js

├── polyfills.bundle.js.map

├── scripts.bundle.js

├── scripts.bundle.js.map

├── styles.bundle.js

├── styles.bundle.js.map

├── vendor.bundle.js

└── vendor.bundle.js.map
```

我们编写的所有代码最终都打包到了前面的文件中。我们将获取`dist`文件夹中的所有文件（而不是`dist`文件夹），然后将其粘贴到`desktop-app/app`文件夹中。在进行前述更改后，桌面应用程序的最终结构将如下所示：

```js
.

├── app

│ ├── favicon.ico

│ ├── index.html

│ ├── inline.bundle.js

│ ├── inline.bundle.js.map

│ ├── main.bundle.js

│ ├── main.bundle.js.map

│ ├── polyfills.bundle.js

│ ├── polyfills.bundle.js.map

│ ├── scripts.bundle.js

│ ├── scripts.bundle.js.map

│ ├── styles.bundle.js

│ ├── styles.bundle.js.map

│ ├── vendor.bundle.js

│ └── vendor.bundle.js.map

├── freeport.js

├── index.css

├── index.html

├── index.js

├── license

├── package.json

├── readme.md

└── server.js
```

要进行测试，请运行以下命令：

```js
npm start
```

然后当我们导航到 VIEW DEVICE 页面时，我们应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00098.jpeg)

通过这样，我们已经完成了桌面应用程序的开发。在下一节中，我们将更新移动应用程序。

# 更新移动应用程序模板

在上一节中，我们已经更新了桌面应用程序。在本节中，我们将更新移动应用程序模板以显示三轴数据。

首先，我们要更新 view-device 模板。按照以下步骤更新`mobile-app/src/pages/view-device/view-device.html`：

```js
<ion-header>
    <ion-navbar>
        <ion-title>Mobile App</ion-title>
    </ion-navbar>
</ion-header>
<ion-content padding>
    <div *ngIf="!lastRecord">
        <h3 class="text-center">Loading!</h3>
    </div>
    <div *ngIf="lastRecord">
        <ion-list>
            <ion-item>
                <ion-label>Name</ion-label>
                <ion-label>{{device.name}}</ion-label>
            </ion-item>
            <ion-item>
                <ion-label>X-Axis</ion-label>
                <ion-label>{{lastRecord.data.acclVals.x}} {{lastRecord.data.acclVals.units}}</ion-label>
            </ion-item>
            <ion-item>
                <ion-label>Y-Axis</ion-label>
                <ion-label>{{lastRecord.data.acclVals.y}} {{lastRecord.data.acclVals.units}}</ion-label>
            </ion-item>
            <ion-item>
                <ion-label>Z-Axis</ion-label>
                <ion-label>{{lastRecord.data.acclVals.z}} {{lastRecord.data.acclVals.units}}</ion-label>
            </ion-item>
            <ion-item>
                <ion-label>Location</ion-label>
                <ion-label>{{lastRecord.data.location.city}}, {{lastRecord.data.location.region}}, {{lastRecord.data.location.country}}</ion-label>
            </ion-item>
            <ion-item>
                <ion-label>Received At</ion-label>
                <ion-label>{{lastRecord.createdAt | date: 'medium'}}</ion-label>
            </ion-item>
        </ion-list>
    </div>
</ion-content>
```

接下来，按照以下步骤更新`mobile-app/src/pages/view-device/view-device.ts`：

```js
import { Component } from '@angular/core'; 
import { IonicPage, NavController, NavParams } from 'ionic-angular'; 

import { DevicesService } from '../../services/device.service'; 
import { DataService } from '../../services/data.service'; 
import { ToastService } from '../../services/toast.service'; 
import { SocketService } from '../../services/socket.service'; 

@IonicPage() 
@Component({ 
   selector: 'page-view-device', 
   templateUrl: 'view-device.html', 
}) 
export class ViewDevicePage { 
   device: any; 
   data: Array<any>; 
   toggleState: boolean = false; 
   private subData: any; 
   lastRecord: any; 

   constructor(private navCtrl: NavController, 
         private navParams: NavParams, 
         private socketService: SocketService, 
         private deviceService: DevicesService, 
         private dataService: DataService, 
         private toastService: ToastService) { 
         this.device = navParams.get("device"); 
         console.log(this.device); 
   } 

   ionViewDidLoad() { 
         this.deviceService.getOne(this.device._id).subscribe((response) => { 
               this.device = response.json(); 
               this.getData(); 
               this.socketInit(); 
         }); 
   } 

   getData() { 
         this.dataService.get(this.device.macAddress).subscribe((response) => { 
               this.data = response.json(); 
               this.lastRecord = this.data[0]; // descending order data 
         }); 
   } 

   socketInit() { 
         this.subData = this.socketService.getData(this.device.macAddress).subscribe((data) => { 
               if (this.data.length <= 0) return; 
               this.data.splice(this.data.length - 1, 1); // remove the last record 
               this.data.push(data); // add the new one 
               this.lastRecord = data; 
         }); 
   } 

   ionViewDidUnload() { 
         this.subData && this.subData.unsubscribe && this.subData.unsubscribe(); //unsubscribe if subData is defined 
   } 
} 
```

保存所有文件，并通过`ionic serve`或`ionic cordova run android`来运行移动应用程序。

然后我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00099.gif)

通过这样，我们已经完成了在移动应用程序上显示智能可穿戴设备数据的工作。

# 摘要

在本章中，我们已经看到如何使用 Raspberry Pi 3 构建一个简单的智能可穿戴设备。我们设置了一个液晶显示屏和一个三轴加速度计，并在显示屏上显示了位置信息。我们实时将加速度计数据发布到云端，并在 Web、桌面和移动应用程序上显示出来。

在第七章，*智能可穿戴设备和 IFTTT*中，我们将通过在其上实施 IFTTT 规则，将智能可穿戴设备提升到一个新的水平。我们将执行诸如打电话或向急救联系人发送短信等操作，以便及时提供护理。


# 第七章：智能可穿戴和 IFTTT

在第六章 *智能可穿戴*中，我们看到了如何构建一个简单的可穿戴设备，显示用户的位置并读取加速计值。在本章中，我们将通过在设备上实现跌倒检测逻辑，然后在数据上添加**If This Then That**（**IFTTT**）规则，将该应用程序提升到下一个级别。我们将讨论以下主题：

+   什么是 IFTTT

+   IFTTT 和物联网

+   了解跌倒检测

+   基于加速计的跌倒检测

+   构建一个 IFTTT 规则引擎

# IFTTT 和物联网

这种反应模式可以轻松应用于某些情况。例如，如果病人摔倒，就叫救护车，或者如果温度低于 15 度，就关闭空调，等等。这些都是我们定义的简单规则，可以帮助我们自动化许多流程。

在物联网中，规则引擎是自动化大部分单调任务的关键。在本章中，我们将构建一个简单的硬编码规则引擎，将持续监视传入的数据。如果传入的数据与我们的任何规则匹配，它将执行一个响应。

我们正在构建的东西类似于[ifttt.com](https://ifttt.com/)（[`ifttt.com/discover`](https://ifttt.com/discover)）的概念，但非常特定于我们框架内存在的物联网设备。IFTTT（[`ifttt.com/discover`](https://ifttt.com/discover)）与我们在书中构建的内容无关。

# 跌倒检测

在第六章 *智能可穿戴*中，我们从加速计中收集了三个轴的值。现在，我们将利用这些数据来检测跌倒。

我建议观看视频*自由落体中的加速计*（[`www.youtube.com/watch?v=-om0eTXsgnY`](https://www.youtube.com/watch?v=-om0eTXsgnY)），它解释了加速计在静止和运动时的行为。

现在我们了解了跌倒检测的基本概念，让我们谈谈我们的具体用例。

跌倒检测中最大的挑战是区分跌倒和其他活动，比如跑步和跳跃。在本章中，我们将保持简单，处理非常基本的条件，即用户静止或持续运动时突然摔倒。

为了确定用户是否摔倒，我们使用信号幅度矢量或*SMV*。*SMV*是三个轴的值的均方根。也就是说：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00100.jpeg)

如果我们开始绘制用户在站立不动然后摔倒时的**SMV**随**时间**的图表，我们将得到以下图表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00101.jpeg)

请注意图表末端的尖峰。这是用户实际摔倒的点。

现在，当我们从 ADXL345 收集加速计值时，我们将计算 SMV。通过使用我们构建的智能可穿戴进行多次迭代，我一直能够在 1 g SMV 值处稳定地检测到跌倒。对于小于 1 g SMV 的任何值，用户几乎总是被认为是静止的，而大于 1 g SMV 的任何值都被认为是跌倒。

请注意，我已经将加速计放置在 y 轴垂直于地面的位置。

一旦我们把设置放在一起，您就可以亲自看到 SMV 值随加速计位置的变化而变化。

请注意，如果您正在进行其他活动，比如跳跃或下蹲，可能会触发跌倒检测。您可以调整 1 g SMV 的阈值，以获得一致的跌倒检测。

你也可以参考*使用 3 轴数字加速度计检测人类跌倒*：([`www.analog.com/en/analog-dialogue/articles/detecting-falls-3-axis-digital-accelerometer.html`](http://www.analog.com/en/analog-dialogue/articles/detecting-falls-3-axis-digital-accelerometer.html))，或者*基于加速度计的身体传感器定位用于健康和医疗监测应用* ([`www.ncbi.nlm.nih.gov/pmc/articles/PMC3279922/`](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC3279922/))，以及*开发用于检测日常活动中跌倒的算法，使用 2 个三轴加速度计* ([`waset.org/publications/2993/development-of-the-algorithm-for-detecting-falls-during-daily-activity-using-2-tri-axial-accelerometers`](http://waset.org/publications/2993/development-of-the-algorithm-for-detecting-falls-during-daily-activity-using-2-tri-axial-accelerometers))，以便更好地理解这个主题并提高系统的效率。

# 更新树莓派

现在我们知道需要做什么，我们将开始编写代码。

在继续之前，创建一个名为`chapter7`的文件夹，并在其中复制`chapter6`代码。

接下来，打开`pi/index.js`文件。我们将更新 ADXL345 初始化设置，然后开始处理数值。更新`pi/index.js`如下：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt'); 
var GetMac = require('getmac'); 
var request = require('request'); 
var ADXL345 = require('adxl345-sensor'); 
require('events').EventEmitter.prototype._maxListeners = 100; 

var adxl345 = new ADXL345(); // defaults to i2cBusNo 1, i2cAddress 0x53 

var Lcd = require('lcd'), 
    lcd = new Lcd({ 
        rs: 12, 
        e: 21, 
        data: [5, 6, 17, 18], 
        cols: 8, 
        rows: 2 
    }); 

var aclCtr = 0, 
    locCtr = 0; 

var prevX, prevY, prevZ, prevSMV, prevFALL; 
var locationG; // global location variable 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('rpi'); 
    client.subscribe('socket'); 
    GetMac.getMac(function(err, mac) { 
        if (err) throw err; 
        macAddress = mac; 
        displayLocation(); 
        initADXL345(); 
        client.publish('api-engine', mac); 
    }); 
}); 

client.on('message', function(topic, message) { 
    message = message.toString(); 
    if (topic === 'rpi') { 
        console.log('API Engine Response >> ', message); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 

function initADXL345() { 
    adxl345.init() 
        .then(() => adxl345.setMeasurementRange(ADXL345.RANGE_2_G())) 
        .then(() => adxl345.setDataRate(ADXL345.DATARATE_100_HZ())) 
        .then(() => adxl345.setOffsetX(0)) // measure for your particular device 
        .then(() => adxl345.setOffsetY(0)) // measure for your particular device 
        .then(() => adxl345.setOffsetZ(0)) // measure for your particular device 
        .then(() => adxl345.getMeasurementRange()) 
        .then((range) => { 
            console.log('Measurement range:', ADXL345.stringifyMeasurementRange(range)); 
            return adxl345.getDataRate(); 
        }) 
        .then((rate) => { 
            console.log('Data rate: ', ADXL345.stringifyDataRate(rate)); 
            return adxl345.getOffsets(); 
        }) 
        .then((offsets) => { 
            console.log('Offsets: ', JSON.stringify(offsets, null, 2)); 
            console.log('ADXL345 initialization succeeded'); 
            loop(); 
        }) 
        .catch((err) => console.error('ADXL345 initialization failed:', err)); 
} 

function loop() { 
    // infinite loop, with 3 seconds delay 
    setInterval(function() { 
        // wait till we get the location 
        // then start processing 
        if (!locationG) return; 

        readSensorValues(function(acclVals) { 
            var x = acclVals.x; 
            var y = acclVals.y; 
            var z = acclVals.z; 
            var fall = 0; 
            var smv = Math.sqrt(x * x, y * y, z * z); 

            if (smv > 1) { 
                fall = 1; 
            } 

            acclVals.smv = smv; 
            acclVals.fall = fall; 

            var data2Send = { 
                data: { 
                    acclVals: acclVals, 
                    location: locationG 
                }, 
                macAddress: macAddress 
            }; 

            // no duplicate data 
            if (fall === 1 && (x !== prevX || y !== prevY || z !== prevZ || smv !== prevSMV || fall !== prevFALL)) { 
                console.log('Fall Detected >> ', acclVals); 
                client.publish('accelerometer', JSON.stringify(data2Send)); 
                console.log('Data Published'); 
                prevX = x; 
                prevY = y; 
                prevZ = z; 
            } 
        }); 

        if (locCtr === 600) { // every 5 mins 
            locCtr = 0; 
            displayLocation(); 
        } 

        aclCtr++; 
        locCtr++; 
    }, 500); // every one second 
} 

function readSensorValues(CB) { 
    adxl345.getAcceleration(true) // true for g-force units, else false for m/s² 
        .then(function(acceleration) { 
            if (CB) CB(acceleration); 
        }) 
        .catch((err) => { 
            console.log('ADXL345 read error: ', err); 
        }); 
} 

function displayLocation() { 
    request('http://ipinfo.io', function(error, res, body) { 
        var info = JSON.parse(body); 
        // console.log(info); 
        locationG = info; 
        var text2Print = ''; 
        text2Print += 'City: ' + info.city; 
        text2Print += ' Region: ' + info.region; 
        text2Print += ' Country: ' + info.country + ' '; 
        lcd.setCursor(16, 0); // 1st row     
        lcd.autoscroll(); 
        printScroll(text2Print); 
    }); 
} 

// a function to print scroll 
function printScroll(str, pos) { 
    pos = pos || 0; 

    if (pos === str.length) { 
        pos = 0; 
    } 

    lcd.print(str[pos]); 
    //console.log('printing', str[pos]); 

    setTimeout(function() { 
        return printScroll(str, pos + 1); 
    }, 300); 
} 

// If ctrl+c is hit, free resources and exit. 
process.on('SIGINT', function() { 
    lcd.clear(); 
    lcd.close(); 
    process.exit(); 
});  
```

注意`initADXL345()`。我们将测量范围定义为`2_G`，清除偏移量，然后调用无限循环函数。在这种情况下，我们将`setInterval()`每`500`毫秒运行一次，而不是每`1`秒。`readSensorValues()`每`500`毫秒调用一次，而不是每`3`秒。这是为了确保我们能够及时捕捉到跌倒。

在`readSensorValues()`中，一旦`x`、`y`和`z`值可用，我们就计算 SMV。然后，我们检查 SMV 值是否大于`1`：如果是，那么我们就检测到了跌倒。

除了`x`、`y`和`z`值之外，我们还发送 SMV 值以及跌倒值到 API 引擎。还要注意，在这个例子中，我们并不是在收集所有值后立即发送数据。我们只有在检测到跌倒时才发送数据。

保存所有文件。通过从`chapter7/broker`文件夹运行以下命令来启动代理：

```js
mosca -c index.js -v | pino  
```

接下来，通过从`chapter7/api-engine`文件夹运行以下命令来启动 API 引擎：

```js
npm start  
```

我们还没有将 IFTTT 逻辑添加到 API 引擎中，这将在下一节中完成。目前，为了验证我们的设置，让我们通过执行在树莓派上的`index.js`文件来开始：

```js
npm start  
```

如果一切顺利，加速度计应该成功初始化，并且数据应该开始传入。

如果我们模拟自由落体，我们应该看到我们的第一条数据发送到 API 引擎，并且它应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00102.jpeg)

正如你所看到的，模拟的自由落体给出了`2.048` g 的 SMV。

我的硬件设置如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00103.jpeg)

我将整个设置粘贴到了**聚苯乙烯**板上，这样我就可以舒适地测试跌倒检测逻辑。

在我确定自由落体的 SMV 时，我从设置中移除了 16 x 2 LCD。

在下一节中，我们将读取从设备接收到的数据，然后根据数据执行规则。

# 构建 IFTTT 规则引擎

现在我们正在将所需的数据发送到 API 引擎，我们将做两件事：

1.  在网页、桌面和移动应用程序上显示我们从智能可穿戴设备得到的数据

1.  在数据之上执行规则

我们将首先开始第二个目标。我们将构建一个规则引擎来根据我们收到的数据执行规则。

让我们从在`api-engine/server`文件夹的根目录下创建一个名为`ifttt`的文件夹开始。在`ifttt`文件夹中，创建一个名为`rules.json`的文件。更新`api-engine/server/ifttt/rules.json`如下：

```js
[{ 
    "device": "b8:27:eb:39:92:0d", 
    "rules": [ 
    { 
        "if": 
        { 
            "prop": "fall", 
            "cond": "eq", 
            "valu": 1 
        }, 
        "then": 
        { 
            "action": "EMAIL", 
            "to": "arvind.ravulavaru@gmail.com" 
        } 
    }] 
}] 
```

从前面的代码中可以看出，我们正在维护一个包含所有规则的 JSON 文件。在我们的情况下，每个设备只有一个规则，规则有两部分：`if`部分和`then`部分。`if`指的是需要针对传入数据进行检查的属性，检查条件以及需要进行检查的值。`then`部分指的是如果`if`匹配，则需要执行的操作。在前面的情况下，此操作涉及发送电子邮件。

接下来，我们将构建规则引擎本身。在`api-engine/server/ifttt`文件夹内创建一个名为`ifttt.js`的文件，并更新`api-engine/server/ifttt/ifttt.js`，如下所示：

```js
var Rules = require('./rules.json'); 

exports.processData = function(data) { 

    for (var i = 0; i < Rules.length; i++) { 
        if (Rules[i].device === data.macAddress) { 
            // the rule belows to the incoming device's data 
            for (var j = 0; j < Rules[i].rules.length; j++) { 
                // process one rule at a time 
                var rule = Rules[i].rules[j]; 
                var data = data.data.acclVals; 
                if (checkRuleAndData(rule, data)) { 
                    console.log('Rule Matched', 'Processing Then.'); 
                    if (rule.then.action === 'EMAIL') { 
                        console.log('Sending email to', rule.then.to); 
                        EMAIL(rule.then.to); 
                    } else { 
                        console.log('Unknown Then! Please re-check the rules'); 
                    } 
                } else { 
                    console.log('Rule Did Not Matched', rule, data); 
                } 
            } 
        } 
    } 
} 

/*   Rule process Helper  */ 
function checkRuleAndData(rule, data) { 
    var rule = rule.if; 
    if (rule.cond === 'lt') { 
        return rule.valu < data[rule['prop']]; 
    } else if (rule.cond === 'lte') { 
        return rule.valu <= data[rule['prop']]; 
    } else if (rule.cond === 'eq') { 
        return rule.valu === data[rule['prop']]; 
    } else if (rule.cond === 'gte') { 
        return rule.valu >= data[rule['prop']]; 
    } else if (rule.cond === 'gt') { 
        return rule.valu > data[rule['prop']]; 
    } else if (rule.cond === 'ne') { 
        return rule.valu !== data[rule['prop']]; 
    } else { 
        return false; 
    } 
} 

/*Then Helpers*/ 
function SMS() { 
    /// AN EXAMPLE TO SHOW OTHER THENs 
} 

function CALL() { 
    /// AN EXAMPLE TO SHOW OTHER THENs 
} 

function PUSHNOTIFICATION() { 
    /// AN EXAMPLE TO SHOW OTHER THENs 
} 

function EMAIL(to) { 
    /// AN EXAMPLE TO SHOW OTHER THENs 
    var email = require('emailjs'); 
    var server = email.server.connect({ 
        user: 'arvind.ravulavaru@gmail.com', 
        password: 'XXXXXXXXXX', 
        host: 'smtp.gmail.com', 
        ssl: true 
    }); 

    server.send({ 
        text: 'Fall has been detected. Please attend to the patient', 
        from: 'Patient Bot <arvind.ravulavaru@gmail.com>', 
        to: to, 
        subject: 'Fall Alert!!' 
    }, function(err, message) { 
        if (err) { 
            console.log('Message sending failed!', err); 
        } 
    }); 
} 
```

逻辑非常简单。当新的数据记录到达 API 引擎时，将调用`processData()`。然后，我们从`rules.json`文件中加载所有规则，并对它们进行迭代，以检查当前规则是否适用于传入设备。

如果是，则通过传递规则和传入数据来调用`checkRuleAndData()`，以检查当前数据集是否与预定义规则匹配。如果是，我们将检查动作，我们的情况是发送电子邮件。您可以在代码中更新相应的电子邮件凭据。

完成后，我们需要在`api-engine/server/mqtt/index.js client.on('message')`中使用`topic`等于`accelerometer`来调用`processData()`。

更新`client.on('message')`，如下所示：

```js
client.on('message', function(topic, message) { 
    // message is Buffer 
    // console.log('Topic >> ', topic); 
    // console.log('Message >> ', message.toString()); 
    if (topic === 'api-engine') { 
        var macAddress = message.toString(); 
        console.log('Mac Address >> ', macAddress); 
        client.publish('rpi', 'Got Mac Address: ' + macAddress); 
    } else if (topic === 'accelerometer') { 
        var data = JSON.parse(message.toString()); 
        console.log('data >> ', data); 
        // create a new data record for the device 
        Data.create(data, function(err, data) { 
            if (err) return console.error(err); 
            // if the record has been saved successfully,  
            // websockets will trigger a message to the web-app 
            // console.log('Data Saved :', data.data); 
            // Invoke IFTTT Rules Engine 
            RulesEngine.processData(data); 
        }); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 
```

就是这样。我们已经准备好了 IFTTT 引擎运行所需的所有部件。

保存所有文件并重新启动 API 引擎。现在，模拟一次跌倒，我们应该看到一封电子邮件，内容应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00104.jpeg)

现在我们已经完成了 IFTTT 引擎，我们将更新界面以反映我们收集到的新数据。

# 更新 Web 应用程序

要更新 Web 应用程序，请打开`web-app/src/app/device/device.component.html`并进行如下更新：

```js
<div class="container"> 
  <br> 
  <div *ngIf="!device"> 
    <h3 class="text-center">Loading!</h3> 
  </div> 
  <div class="row" *ngIf="lastRecord"> 
    <div class="col-md-12"> 
      <div class="panel panel-info"> 
        <div class="panel-heading"> 
          <h3 class="panel-title"> 
                        {{device.name}} 
                    </h3> 
          <span class="pull-right btn-click"> 
                        <i class="fa fa-chevron-circle-up"></i> 
                    </span> 
        </div> 
        <div class="clearfix"></div> 
        <div class="table-responsive"> 
          <table class="table table-striped"> 
            <tr *ngIf="lastRecord"> 
              <td>X-Axis</td> 
              <td>{{lastRecord.data.acclVals.x}} {{lastRecord.data.acclVals.units}}</td> 
            </tr> 
            <tr *ngIf="lastRecord"> 
              <td>Y-Axis</td> 
              <td>{{lastRecord.data.acclVals.y}} {{lastRecord.data.acclVals.units}}</td> 
            </tr> 
            <tr *ngIf="lastRecord"> 
              <td>Z-Axis</td> 
              <td>{{lastRecord.data.acclVals.z}} {{lastRecord.data.acclVals.units}}</td> 
            </tr> 
            <tr *ngIf="lastRecord"> 
              <td>Signal Magnitude Vector</td> 
              <td>{{lastRecord.data.acclVals.smv}}</td> 
            </tr> 
            <tr *ngIf="lastRecord"> 
              <td>Fall State</td> 
              <td>{{lastRecord.data.acclVals.fall ? 'Patient Down' : 'All is well!'}}</td> 
            </tr> 
            <tr *ngIf="lastRecord"> 
              <td>Location</td> 
              <td>{{lastRecord.data.location.city}}, {{lastRecord.data.location.region}}, {{lastRecord.data.location.country}}</td> 
            </tr> 
            <tr *ngIf="lastRecord"> 
              <td>Received At</td> 
              <td>{{lastRecord.createdAt | date : 'medium'}}</td> 
            </tr> 
          </table> 
          <hr> 
          <div class="col-md-12" *ngIf="acclVals.length > 0"> 
            <canvas baseChart [datasets]="acclVals" [labels]="lineChartLabels" [options]="lineChartOptions" [legend]="lineChartLegend" [chartType]="lineChartType"></canvas> 
          </div> 
        </div> 
      </div> 
    </div> 
  </div> 
</div> 
```

保存文件并运行：

```js
npm start
```

一旦我们导航到设备页面，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00105.jpeg)

在下一节中，我们将更新桌面应用程序。

# 更新桌面应用程序

现在 Web 应用程序已经完成，我们将构建相同的内容并将其部署到我们的桌面应用程序中。

要开始，请返回到`web-app`文件夹的终端/提示符并运行：

```js
ng build --env=prod
```

这将在`web-app`文件夹内创建一个名为`dist`的新文件夹。`dist`文件夹的内容应该如下所示：

```js
.

├── favicon.ico

├── index.html

├── inline.bundle.js

├── inline.bundle.js.map

├── main.bundle.js

├── main.bundle.js.map

├── polyfills.bundle.js

├── polyfills.bundle.js.map

├── scripts.bundle.js

├── scripts.bundle.js.map

├── styles.bundle.js

├── styles.bundle.js.map

├── vendor.bundle.js

└── vendor.bundle.js.map
```

我们编写的所有代码最终都被捆绑到了前述文件中。我们将获取`dist`文件夹内的所有文件（而不是`dist`文件夹），然后将它们粘贴到`desktop-app/app`文件夹内。这些更改后桌面应用程序的最终结构将如下所示：

```js
.

├── app

│ ├── favicon.ico

│ ├── index.html

│ ├── inline.bundle.js

│ ├── inline.bundle.js.map

│ ├── main.bundle.js

│ ├── main.bundle.js.map

│ ├── polyfills.bundle.js

│ ├── polyfills.bundle.js.map

│ ├── scripts.bundle.js

│ ├── scripts.bundle.js.map

│ ├── styles.bundle.js

│ ├── styles.bundle.js.map

│ ├── vendor.bundle.js

│ └── vendor.bundle.js.map

├── freeport.js

├── index.css

├── index.html

├── index.js

├── license

├── package.json

├── readme.md

└── server.js
```

进行测试，运行：

```js
npm start  
```

然后，当我们导航到 VIEW DEVICE 页面时，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00106.jpeg)

现在桌面应用程序已经完成，我们将开始处理移动应用程序。

# 更新移动应用程序

为了在移动应用程序中反映新的模板，我们将更新`mobile-app/src/pages/view-device/view-device.html`，如下所示：

```js
<ion-header> 
  <ion-navbar> 
    <ion-title>Mobile App</ion-title> 
  </ion-navbar> 
</ion-header> 
<ion-content padding> 
  <div *ngIf="!lastRecord"> 
    <h3 class="text-center">Loading!</h3> 
  </div> 
  <div *ngIf="lastRecord"> 
    <ion-list> 
      <ion-item> 
        <ion-label>Name</ion-label> 
        <ion-label>{{device.name}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>X-Axis</ion-label> 
        <ion-label>{{lastRecord.data.acclVals.x}} {{lastRecord.data.acclVals.units}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>Y-Axis</ion-label> 
        <ion-label>{{lastRecord.data.acclVals.y}} {{lastRecord.data.acclVals.units}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>Z-Axis</ion-label> 
        <ion-label>{{lastRecord.data.acclVals.z}} {{lastRecord.data.acclVals.units}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>Signal Magnitude Vector</ion-label> 
        <ion-label>{{lastRecord.data.acclVals.smv}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>Fall State</ion-label> 
        <ion-label>{{lastRecord.data.acclVals.fall ? 'Patient Down' : 'All is well!'}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>Location</ion-label> 
        <ion-label>{{lastRecord.data.location.city}}, {{lastRecord.data.location.region}}, {{lastRecord.data.location.country}}</ion-label> 
      </ion-item> 
      <ion-item> 
        <ion-label>Received At</ion-label> 
        <ion-label>{{lastRecord.createdAt | date: 'medium'}}</ion-label> 
      </ion-item> 
    </ion-list> 
  </div> 
</ion-content> 
```

保存所有文件并通过以下方式运行移动应用程序：

```js
ionic serve  
```

您也可以使用：

```js
ionic cordova run android 
```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00107.gif)

# 总结

在本章中，我们使用了跌倒检测和 IFTTT 的概念。使用我们在第六章中构建的智能可穿戴设备，我们添加了跌倒检测逻辑。然后，我们将相同的数据发送到 API 引擎，并在 API 引擎中构建了自己的 IFTTT 规则引擎。我们定义了一个规则，用于在检测到跌倒时发送电子邮件。

除此之外，我们还更新了 Web、桌面和移动应用程序，以反映我们收集到的新数据。

在第八章中，*树莓派图像流*，我们将使用树莓派进行视频监控。


# 第八章：树莓派图像流式传输

在本章中，我们将学习使用树莓派 3 和树莓派摄像头进行实时视频流。我们将从树莓派 3 实时流式传输视频到我们的网络浏览器，并可以在世界各地访问此视频。作为下一步，我们将向当前设置添加运动检测器，如果检测到运动，我们将开始流式传输视频。在本章中，我们将介绍以下主题：

+   理解 MJPEG

+   使用树莓派和树莓派摄像头进行设置

+   实时将摄像头图像流式传输到仪表板

+   捕捉运动中的视频

# MJPEG

引用维基百科，[`en.wikipedia.org/wiki/Motion_JPEG`](https://en.wikipedia.org/wiki/Motion_JPEG)。

在多媒体中，动态 JPEG（M-JPEG 或 MJPEG）是一种视频压缩格式，其中数字视频序列的每个视频帧或隔行场都单独压缩为 JPEG 图像。最初为多媒体 PC 应用程序开发，M-JPEG 现在被视频捕获设备（如数码相机、IP 摄像机和网络摄像头）以及非线性视频编辑系统所使用。它受 QuickTime Player、PlayStation 游戏机和 Safari、Google Chrome、Mozilla Firefox 和 Microsoft Edge 等网络浏览器的本地支持。

如前所述，我们将捕获一系列图像，每隔`100ms`并在一个主题上流式传输图像二进制数据到 API 引擎，我们将用最新的图像覆盖现有图像。

这个流媒体系统非常简单和老式。在流媒体过程中没有倒带或暂停。我们总是能看到最后一帧。

现在我们对我们要实现的目标有了很高的理解水平，让我们开始吧。

# 设置树莓派

使用树莓派 3 设置树莓派摄像头非常简单。您可以从任何知名在线供应商购买树莓派 3 摄像头([`www.raspberrypi.org/products/camera-module-v2/`](https://www.raspberrypi.org/products/camera-module-v2/))。然后您可以按照此视频进行设置：摄像头板设置：[`www.youtube.com/watch?v=GImeVqHQzsE`](https://www.youtube.com/watch?v=GImeVqHQzsE)。

我的摄像头设置如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00108.jpeg)

我使用了一个支架，将我的摄像头吊在上面。

# 设置摄像头

现在我们已经连接了摄像头并由树莓派 3 供电，我们将按照以下步骤设置摄像头：

1.  从树莓派内部，启动一个新的终端并运行：

```js
    sudo raspi-config
```

1.  这将启动树莓派配置屏幕。选择接口选项：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00109.jpeg)

1.  在下一个屏幕上，选择 P1 摄像头并启用它：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00110.jpeg)

1.  这将触发重新启动，完成重新启动并重新登录到树莓派。

一旦您的摄像头设置好了，我们将对其进行测试。

# 测试摄像头

现在摄像头已经设置并通电，让我们来测试一下。打开一个新的终端并在桌面上`cd`。然后运行以下命令：

```js
raspistill -o test.jpg
```

这将在当前工作目录`Desktop`中拍摄屏幕截图。屏幕看起来会像下面这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00111.jpeg)

正如您所看到的，`test.jpg`被创建在`Desktop`上，当我双击它时，显示的是我办公室玻璃墙的照片。

# 开发逻辑

现在我们能够测试摄像头，我们将把这个设置与我们的物联网平台集成。我们将不断地以`100ms`的间隔流式传输这些图像到我们的 API 引擎，然后通过网络套接字更新网络上的用户界面。

要开始，我们将复制`chapter4`并将其转储到名为`chapter8`的文件夹中。在`chapter8`文件夹中，打开`pi/index.js`并进行以下更新：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt'); 
var GetMac = require('getmac'); 
var Raspistill = require('node-raspistill').Raspistill; 
var raspistill = new Raspistill({ 
    noFileSave: true, 
    encoding: 'jpg', 
    width: 640, 
    height: 480 
}); 

var crypto = require("crypto"); 
var fs = require('fs'); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('rpi'); 
    GetMac.getMac(function(err, mac) { 
        if (err) throw err; 
        macAddress = mac; 
        client.publish('api-engine', mac); 
        startStreaming(); 
    }); 

}); 

client.on('message', function(topic, message) { 
    message = message.toString(); 
    if (topic === 'rpi') { 
        console.log('API Engine Response >> ', message); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 

function startStreaming() { 
    raspistill 
        .timelapse(100, 0, function(image) { // every 100ms ~~FOREVER~~ 
            var data2Send = { 
                data: { 
                    image: image, 
                    id: crypto.randomBytes(8).toString("hex") 
                }, 
                macAddress: macAddress 
            }; 

            client.publish('image', JSON.stringify(data2Send)); 
            console.log('[image]', 'published'); 
        }) 
        .then(function() { 
            console.log('Timelapse Ended') 
        }) 
        .catch(function(err) { 
            console.log('Error', err); 
        }); 
} 
```

正如我们从前面的代码中所看到的，我们正在等待 MQTT 连接完成，一旦连接完成，我们调用`startStreaming()`开始流式传输。在`startStreaming()`内部，我们调用`raspistill.timelapse()`传入`100ms`，作为每次点击之间的时间差，`0`表示捕获应该持续不断地进行。

一旦图像被捕获，我们就用一个随机 ID、图像缓冲区和设备的`macAddress`构造`data2Send`对象。在发布到图像主题之前，我们将`data2Send`对象转换为字符串。

现在，将这个文件移动到树莓派的`pi-client`文件夹中，位于桌面上。然后从树莓派的`pi-client`文件夹内运行：

```js
npm install && npm install node-raspistill --save  
```

这两个命令将安装`node-raspistill`和`package.json`文件内的其他节点模块。

有了这个，我们完成了树莓派和相机的设置。在下一节中，我们将更新 API 引擎以接受图像的实时流。

# 更新 API 引擎

现在我们完成了树莓派的设置，我们将更新 API 引擎以接受传入的数据。

我们要做的第一件事是按照以下方式更新`api-engine/server/mqtt/index.js`：

```js
var Data = require('../api/data/data.model'); 
var mqtt = require('mqtt'); 
var config = require('../config/environment'); 
var fs = require('fs'); 
var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    console.log('Connected to Mosca at ' + config.mqtt.host + ' on port ' + config.mqtt.port); 
    client.subscribe('api-engine'); 
    client.subscribe('image'); 
}); 

client.on('message', function(topic, message) { 
    // message is Buffer 
    // console.log('Topic >> ', topic); 
    // console.log('Message >> ', message.toString()); 
    if (topic === 'api-engine') { 
        var macAddress = message.toString(); 
        console.log('Mac Address >> ', macAddress); 
        client.publish('rpi', 'Got Mac Address: ' + macAddress); 
    } else if (topic === 'image') { 
        message = JSON.parse(message.toString()); 
        // convert string to buffer 
        var image = Buffer.from(message.data.image, 'utf8'); 
        var fname = 'stream_' + ((message.macAddress).replace(/:/g, '_')) + '.jpg'; 
        fs.writeFile(__dirname + '/stream/' + fname, image, { encoding: 'binary' }, function(err) { 
            if (err) { 
                console.log('[image]', 'save failed', err); 
            } else { 
                console.log('[image]', 'saved'); 
            } 
        }); 

        // as of now we are not going to 
        // store the image buffer in DB.  
        // Gridfs would be a good way 
        // instead of storing a stringified text 
        delete message.data.image; 
        message.data.fname = fname; 

        // create a new data record for the device 
        Data.create(message, function(err, data) { 
            if (err) return console.error(err); 
            // if the record has been saved successfully,  
            // websockets will trigger a message to the web-app 
            // console.log('Data Saved :', data); 
        }); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 
```

正如我们从前面的代码中所看到的，在 MQTT 的消息事件中，我们添加了一个名为`image`的新主题。在这个主题内，我们提取了图像缓冲区的字符串格式，并将其转换回图像二进制数据。然后使用`fs`模块，我们一遍又一遍地覆盖相同的图像。

我们同时将数据保存到 MongoDB，并触发一个 socket emit。

作为下一步，我们需要在`mqtt`文件夹内创建一个名为`stream`的文件夹。在这个文件夹内，放入一个图片，链接在这里：`http://www.iconarchive.com/show/small-n-flat-icons-by-paomedia/sign-ban-icon.html.` 如果相机没有可用的视频流，将显示这张图片。

所有的图像都将保存在`stream`文件夹内，对于相同的设备将更新相同的图像，正如前面提到的，不会有任何倒带或重播。

现在，图片被保存在`stream`文件夹内，我们需要暴露一个端点来将这张图片发送给请求的客户端。为此，打开`api-engine/server/routes.js`并将以下内容添加到`module.exports`函数中：

```js
app.get('/stream/:fname', function(req, res, next) { 
        var fname = req.params.fname; 
        var streamDir = __dirname + '/mqtt/stream/'; 
        var img = streamDir + fname; 
        console.log(img); 
        fs.exists(img, function(exists) { 
         if (exists) { 
                return res.sendFile(img); 
            } else { 
                // http://www.iconarchive.com/show/small-n-flat-icons-by-paomedia/sign-ban-icon.html 
                return res.sendFile(streamDir + '/no-image.png'); 
            } 
        }); 
    });  
```

这将负责将图像分发给客户端（Web、桌面和移动端）。

有了这个，我们就完成了 API 引擎的设置。

保存所有文件并启动代理、API 引擎和`pi-client`。如果一切顺利设置，我们应该能看到来自树莓派的数据被发布。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00112.jpeg)

以及在 API 引擎中出现的相同数据：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00113.jpeg)

此时，图像正在被捕获并通过 MQTT 发送到 API 引擎。下一步是实时查看这些图像。

# 更新 Web 应用程序

现在数据正在流向 API 引擎，我们将在 Web 应用程序上显示它。打开`web-app/src/app/device/device.component.html`并按照以下方式更新它：

```js
<div class="container"> 
    <br> 
    <div *ngIf="!device"> 
        <h3 class="text-center">Loading!</h3> 
    </div> 
    <div class="row" *ngIf="!lastRecord"> 
        <h3 class="text-center">No Data!</h3> 
    </div> 
    <div class="row" *ngIf="lastRecord"> 
        <div class="col-md-12"> 
            <div class="panel panel-info"> 
                <div class="panel-heading"> 
                    <h3 class="panel-title"> 
                        {{device.name}} 
                    </h3> 
                    <span class="pull-right btn-click"> 
                        <i class="fa fa-chevron-circle-up"></i> 
                    </span> 
                </div> 
                <div class="clearfix"></div> 
                <div class="table-responsive" *ngIf="lastRecord"> 
                    <table class="table table-striped"> 
                        <tr> 
                            <td colspan="2" class="text-center"><img  [src]="lastRecord.data.fname"></td> 
                        </tr> 
                        <tr class="text-center" > 
                            <td>Received At</td> 
                            <td>{{lastRecord.createdAt | date: 'medium'}}</td> 
                        </tr> 
                    </table> 
                </div> 
            </div> 
        </div> 
    </div> 
</div> 
```

在这里，我们实时显示了我们创建的图像。接下来，按照以下方式更新`web-app/src/app/device/device.component.ts`：

```js
import { Component, OnInit, OnDestroy } from '@angular/core'; 
import { DevicesService } from '../services/devices.service'; 
import { Params, ActivatedRoute } from '@angular/router'; 
import { SocketService } from '../services/socket.service'; 
import { DataService } from '../services/data.service'; 
import { NotificationsService } from 'angular2-notifications'; 
import { Globals } from '../app.global'; 

@Component({ 
   selector: 'app-device', 
   templateUrl: './device.component.html', 
   styleUrls: ['./device.component.css'] 
}) 
export class DeviceComponent implements OnInit, OnDestroy { 
   device: any; 
   data: Array<any>; 
   toggleState: boolean = false; 
   private subDevice: any; 
   private subData: any; 
   lastRecord: any; 

   // line chart config 

   constructor(private deviceService: DevicesService, 
         private socketService: SocketService, 
         private dataService: DataService, 
         private route: ActivatedRoute, 
         private notificationsService: NotificationsService) { } 

   ngOnInit() { 
         this.subDevice = this.route.params.subscribe((params) => { 
               this.deviceService.getOne(params['id']).subscribe((response) => { 
                     this.device = response.json(); 
                     this.getData(); 
               }); 
         }); 
   } 

   getData() { 
         this.dataService.get(this.device.macAddress).subscribe((response) => { 
               this.data = response.json(); 
               let d = this.data[0]; 
               d.data.fname = Globals.BASE_API_URL + 'stream/' + d.data.fname; 
               this.lastRecord = d; // descending order data 
               this.socketInit(); 
         }); 
   } 

   socketInit() { 
         this.subData = this.socketService.getData(this.device.macAddress).subscribe((data: any) => { 
               if (this.data.length <= 0) return; 
               this.data.splice(this.data.length - 1, 1); // remove the last record 
               data.data.fname = Globals.BASE_API_URL + 'stream/' + data.data.fname + '?t=' + (Math.random() * 100000); // cache busting 
               this.data.push(data); // add the new one 
               this.lastRecord = data; 
         }); 
   }
```

```js
   ngOnDestroy() { 
         this.subDevice.unsubscribe(); 
         this.subData ? this.subData.unsubscribe() : ''; 
   } 
} 
```

在这里，我们正在构建图像 URL 并将其指向 API 引擎。保存所有文件，并通过在`web-app`文件夹内运行以下命令来启动 Web 应用程序：

```js
npm start  
```

如果一切按预期工作，当导航到“查看设备”页面时，我们应该会看到视频流非常缓慢地显示。我正在监视放在椅子前面的杯子，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00114.jpeg)

# 更新桌面应用程序

现在 Web 应用程序已经完成，我们将构建相同的应用程序并将其部署到我们的桌面应用程序内。

要开始，请返回到`web-app`文件夹的终端/提示符，并运行以下命令：

```js
ng build --env=prod  
```

这将在`web-app`文件夹内创建一个名为`dist`的新文件夹。`dist`文件夹的内容应该如下所示：

```js
.

├── favicon.ico

├── index.html

├── inline.bundle.js

├── inline.bundle.js.map

├── main.bundle.js

├── main.bundle.js.map

├── polyfills.bundle.js

├── polyfills.bundle.js.map

├── scripts.bundle.js

├── scripts.bundle.js.map

├── styles.bundle.js

├── styles.bundle.js.map

├── vendor.bundle.js

└── vendor.bundle.js.map
```

我们编写的所有代码最终都打包到了上述文件中。我们将获取`dist`文件夹中的所有文件（不包括`dist`文件夹），然后将其粘贴到`desktop-app/app`文件夹中。在进行上述更改后，`desktop-app`的最终结构将如下所示：

```js
.

├── app

│ ├── favicon.ico

│ ├── index.html

│ ├── inline.bundle.js

│ ├── inline.bundle.js.map

│ ├── main.bundle.js

│ ├── main.bundle.js.map

│ ├── polyfills.bundle.js

│ ├── polyfills.bundle.js.map

│ ├── scripts.bundle.js

│ ├── scripts.bundle.js.map

│ ├── styles.bundle.js

│ ├── styles.bundle.js.map

│ ├── vendor.bundle.js

│ └── vendor.bundle.js.map

├── freeport.js

├── index.css

├── index.html

├── index.js

├── license

├── package.json

├── readme.md

└── server.js
```

进行测试，运行以下命令：

```js
npm start 
```

然后当我们导航到 VIEW DEVICE 页面时，我们应该看到：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00115.jpeg)

这样我们就完成了桌面应用程序的开发。在下一节中，我们将更新移动应用程序。

# 更新移动应用程序

在上一节中，我们已经更新了桌面应用程序。在本节中，我们将更新移动应用程序模板以流式传输图像。

首先，我们将更新 view-device 模板。按照以下方式更新`mobile-app/src/pages/view-device/view-device.html`：

```js
<ion-header> 
    <ion-navbar> 
        <ion-title>Mobile App</ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <div *ngIf="!lastRecord"> 
        <h3 class="text-center">Loading!</h3> 
    </div> 
    <div *ngIf="lastRecord"> 
        <ion-list> 
            <ion-item> 
                <img [src]="lastRecord.data.fname"> 
            </ion-item> 
            <ion-item> 
                <ion-label>Received At</ion-label> 
                <ion-label>{{lastRecord.createdAt | date: 'medium'}}</ion-label> 
            </ion-item> 
        </ion-list> 
    </div> 
</ion-content> 
```

在移动端显示图像流的逻辑与 Web/桌面端相同。接下来，按照以下方式更新`mobile-app/src/pages/view-device/view-device.ts`：

```js
import { Component } from '@angular/core'; 
import { IonicPage, NavController, NavParams } from 'ionic-angular'; 
import { Globals } from '../../app/app.globals'; 
import { DevicesService } from '../../services/device.service'; 
import { DataService } from '../../services/data.service'; 
import { ToastService } from '../../services/toast.service'; 
import { SocketService } from '../../services/socket.service'; 

@IonicPage() 
@Component({ 
   selector: 'page-view-device', 
   templateUrl: 'view-device.html', 
}) 
export class ViewDevicePage { 
   device: any; 
   data: Array<any>; 
   toggleState: boolean = false; 
   private subData: any; 
   lastRecord: any; 

   constructor(private navCtrl: NavController, 
         private navParams: NavParams, 
         private socketService: SocketService, 
         private deviceService: DevicesService, 
         private dataService: DataService, 
         private toastService: ToastService) { 
         this.device = navParams.get("device"); 
         console.log(this.device); 
   } 

   ionViewDidLoad() { 
         this.deviceService.getOne(this.device._id).subscribe((response) => { 
               this.device = response.json(); 
               this.getData(); 
         }); 
   } 

   getData() { 
         this.dataService.get(this.device.macAddress).subscribe((response) => { 
               this.data = response.json(); 
               let d = this.data[0]; 
               d.data.fname = Globals.BASE_API_URL + 'stream/' + d.data.fname; 
               this.lastRecord = d; // descending order data 
               this.socketInit(); 
         }); 
   } 

   socketInit() { 
         this.subData = this.socketService.getData(this.device.macAddress).subscribe((data: any) => { 
               if(this.data.length <= 0) return; 
               this.data.splice(this.data.length - 1, 1); // remove the last record 
               data.data.fname = Globals.BASE_API_URL + 'stream/' + data.data.fname + '?t=' + (Math.random() * 100000); 
               this.data.push(data); // add the new one 
               this.lastRecord = data; 
         }); 
   } 

   ionViewDidUnload() { 
         this.subData && this.subData.unsubscribe && this.subData.unsubscribe(); //unsubscribe if subData is defined 
   } 
} 
```

保存所有文件并通过以下方式运行移动应用程序：

```js
ionic serve  
```

或者使用以下代码：

```js
ionic cordova run android  
```

然后我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00116.jpeg)

这样我们就完成了在移动应用程序上显示摄像头数据。

# 基于运动的视频捕获

正如我们所看到的，流式传输有些不连贯，缓慢，并非实时，另一个可能的解决方案是在树莓派和摄像头上放置一个运动检测器。然后当检测到运动时，我们开始录制 10 秒的视频。然后将此视频作为附件通过电子邮件发送给用户。

现在，我们将开始更新我们现有的代码。

# 更新树莓派

首先，我们将更新我们的树莓派设置以适应 HC-SR501 PIR 传感器。您可以在此处找到 PIR 传感器：[`www.amazon.com/Motion-HC-SR501-Infrared-Arduino-Raspberry/dp/B00M1H7KBW/ref=sr_1_4_a_it`](https://www.amazon.com/Motion-HC-SR501-Infrared-Arduino-Raspberry/dp/B00M1H7KBW/ref=sr_1_4_a_it)。

我们将把 PIR 传感器连接到树莓派的 17 号引脚，将摄像头连接到摄像头插槽，就像我们之前看到的那样。

一旦连接如前所述，按照以下方式更新`pi/index.js`：

```js
var config = require('./config.js'); 
var mqtt = require('mqtt'); 
var GetMac = require('getmac'); 
var Raspistill = require('node-raspistill').Raspistill; 
var crypto = require("crypto"); 
var fs = require('fs'); 
var Gpio = require('onoff').Gpio; 
var exec = require('child_process').exec; 

var pir = new Gpio(17, 'in', 'both'); 
var raspistill = new Raspistill({ 
    noFileSave: true, 
    encoding: 'jpg', 
    width: 640, 
    height: 480 
}); 

var client = mqtt.connect({ 
    port: config.mqtt.port, 
    protocol: 'mqtts', 
    host: config.mqtt.host, 
    clientId: config.mqtt.clientId, 
    reconnectPeriod: 1000, 
    username: config.mqtt.clientId, 
    password: config.mqtt.clientId, 
    keepalive: 300, 
    rejectUnauthorized: false 
}); 

client.on('connect', function() { 
    client.subscribe('rpi'); 
    GetMac.getMac(function(err, mac) { 
        if (err) throw err; 
        macAddress = mac; 
        client.publish('api-engine', mac); 
        // startStreaming(); 
    }); 

}); 

client.on('message', function(topic, message) { 
    message = message.toString(); 
    if (topic === 'rpi') { 
        console.log('API Engine Response >> ', message); 
    } else { 
        console.log('Unknown topic', topic); 
    } 
}); 

function startStreaming() { 
    raspistill 
        .timelapse(100, 0, function(image) { // every 100ms ~~FOREVER~~ 
            var data2Send = { 
                data: { 
                    image: image, 
                    id: crypto.randomBytes(8).toString("hex") 
                }, 
                macAddress: macAddress 
            }; 

            client.publish('image', JSON.stringify(data2Send)); 
            console.log('[image]', 'published'); 
        }) 
        .then(function() { 
            console.log('Timelapse Ended') 
        }) 
        .catch(function(err) { 
            console.log('Error', err); 
        }); 
} 

var isRec = false; 

// keep watching for motion 
pir.watch(function(err, value) { 
    if (err) exit(); 
    if (value == 1 && !isRec) { 
        console.log('Intruder detected'); 
        console.log('capturing video.. '); 
        isRec = true; 
        var videoPath = __dirname + '/video.h264'; 
        var file = fs.createWriteStream(videoPath); 
        var video_path = './video/video' + Date.now() + '.h264'; 
        var cmd = 'raspivid -o ' + video_path + ' -t 5000'; 

        exec(cmd, function(error, stdout, stderr) { 
            // output is in stdout 
            console.log('Video Saved @ : ', video_path); 
            require('./mailer').sendEmail(video_path, true, function(err, info) { 
                setTimeout(function() { 
                    // isRec = false; 
                }, 3000); // don't allow recording for 3 sec after 
            }); 
        }); 
    } 
}); 

function exit() { 
    pir.unexport(); 
    process.exit(); 
} 
```

从上述代码中可以看出，我们已将 GPIO 17 标记为输入引脚，并将其分配给名为`pir`的变量。接下来，使用`pir.watch()`，我们不断查看运动检测器的值是否发生变化。如果运动检测器检测到某种变化，我们将检查值是否为`1`，这表示触发了运动。然后使用`raspivid`我们录制一个 5 秒的视频并通过电子邮件发送。

为了从树莓派 3 发送电子邮件所需的逻辑，创建一个名为`mailer.js`的新文件，放在`pi-client`文件夹的根目录，并按以下方式更新它：

```js
var fs = require('fs'); 
var nodemailer = require('nodemailer'); 

var transporter = nodemailer.createTransport({ 
    service: 'Gmail', 
    auth: { 
        user: 'arvind.ravulavaru@gmail.com', 
        pass: '**********' 
    } 
}); 

var timerId; 

module.exports.sendEmail = function(file, deleteAfterUpload, cb) { 
    if (timerId) return; 

    timerId = setTimeout(function() { 
        clearTimeout(timerId); 
        timerId = null; 
    }, 10000); 

    console.log('Sendig an Email..'); 

    var mailOptions = { 
        from: 'Pi Bot <pi.intruder.alert@gmail.com>', 
        to: 'user@email.com', 
        subject: '[Pi Bot] Intruder Detected', 
        html: 'Intruder Detected. Please check the video attached. <br/><br/> Intruder Detected At : ' + Date(), 
        attachments: [{ 
            path: file 
        }] 
    }; 

    transporter.sendMail(mailOptions, function(err, info) { 
        if (err) { 
            console.log(err); 
        } else { 
            console.log('Message sent: ' + info.response); 
            if (deleteAfterUpload) { 
                fs.unlink(path); 
            } 
        } 

        if (cb) { 
            cb(err, info); 
        } 
    }); 
} 
```

我们使用 nodemailer 发送电子邮件。根据需要更新凭据。

接下来，运行以下命令：

```js
npm install onoff -save  
```

在下一节中，我们将测试这个设置。

# 测试代码

现在我们已经完成设置，让我们来测试一下。给树莓派供电，如果尚未上传代码，则上传代码，并运行以下命令：

```js
npm start
```

代码运行后，触发一次运动。这将启动摄像头录制并保存 5 秒的视频。然后将此视频通过电子邮件发送给用户。以下是输出的列表：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00117.jpeg)

收到的电子邮件将如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prac-iot-js/img/00118.jpeg)

这是使用树莓派 3 进行监视的另一种方法。

# 总结

在本章中，我们已经看到了使用树莓派进行监视的两种方法。第一种方法是我们将图像流式传输到 API 引擎，然后在移动 Web 和桌面应用程序上使用 MJPEG 进行可视化。第二种方法是检测运动，然后开始录制视频。然后将此视频作为附件通过电子邮件发送。这两种方法也可以结合在一起，如果在第一种方法中检测到运动，则可以开始 MJPEG 流式传输。

在第九章中，*智能监控*，我们将把这个提升到下一个级别，我们将在我们的捕获图像上添加人脸识别，并使用 AWS Rekognition 平台进行人脸识别（而不是人脸检测）。
