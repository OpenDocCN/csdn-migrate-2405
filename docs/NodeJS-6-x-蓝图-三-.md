# NodeJS 6.x 蓝图（三）

> 原文：[`zh.annas-archive.org/md5/9B48011577F790A25E05CA5ABA4F9C8B`](https://zh.annas-archive.org/md5/9B48011577F790A25E05CA5ABA4F9C8B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 MongoDB 地理空间查询创建门店定位器应用程序

在本章中，我们将构建一个应用程序，仅使用 express 框架、Google 地图 API 和纯 JavaScript 存储**地理位置**数据的坐标（纬度和经度），并在地图上显示它们。

如今，使用 JavaScript 库是非常常见的，但大多数情况下它们仅用于应用程序的前端，通常使用 JSON 格式的数据消耗端点，并使用 Ajax 更新 UI。但是我们将仅在后端使用 JavaScript，构建一个 MVC 应用程序。

此外，我们将使用 MongoDB 的一个非常强大的功能，即能够在坐标中生成索引，使用诸如`$near`、`$geometry`等操作符，以定位地图中靠近特定位置的某些记录。

在本章中，我们将涵盖以下主题：

+   在 MongoDB 中创建用于存储坐标的模型/架构

+   创建*2d*球体索引

+   处理 Google Maps API

+   处理 HTML5 地理位置 API

+   在模板中混合 Swig 变量和纯 JavaScript

# 我们正在构建什么

在本章中，我们将构建一个门店定位器应用程序和一个简单的添加门店界面。结果如下截图所示：

![我们正在构建什么](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_001.jpg)

主屏幕

# 创建基线应用程序

我们将使用与第四章中使用的`express-generator`相同的版本，*不要拍照，创造它-为摄影师设计的应用程序*。这次，我们不需要任何额外的模块来完成我们的任务：

1.  创建一个名为`chapter05`的文件夹。

1.  在`chapter05`文件夹中打开您的终端/ shell 并输入以下命令：

```js
 yo express

```

### 提示

请注意，我们已经在第四章中安装了`generator-express`。

1.  现在，按照以下顺序填写问题：

+   选择`N`：我们已经创建了一个文件夹

+   选择`MVC`：作为应用程序类型

+   选择`Swig`：作为模板引擎

+   选择`None`：作为 CSS 预处理器

+   选择`MongoDb`：作为数据库

+   选择`Gulp`：用于 LiveReload 和其他功能

### 提示

如果您从未听说过`Gulp`，不要担心；在本书的后面，我们将看到并解释一些构建工具。

## 重构默认结构

正如我们所知，并且正如我们之前所做的，我们需要对我们的应用程序结构进行一些调整，以使其更具可扩展性并遵循我们的 MVC 模式：

1.  在`app/views`文件夹中，创建一个名为`pages`的文件夹。

1.  在`app/views`文件夹中，创建一个名为`partials`的文件夹。

1.  将所有文件从`views`文件夹移动到`pages`文件夹。

### 为页脚和页眉创建部分视图

现在，作为最佳实践，让我们为页脚和页眉创建一些部分文件：

1.  在`app/view/partials/`中创建一个名为`footer.html`的文件。

1.  在`app/view/partials/`中创建一个名为`head.html`的文件。

### 将 Swig 模板设置为使用 HTML 扩展名

正如您所看到的，我们使用了`.html`文件扩展名，与之前的示例不同，我们使用了`.swig`文件扩展名。因此，我们需要更改 express `app.engine`配置文件，以便使用这种类型的扩展名：

1.  从`app/config/`中打开`express.js`文件。

1.  替换以下突出显示的代码行：

```js
      app.engine('html', swig.renderFile); 
      if(env == 'development'){ 
        app.set('view cache', false); 
        swig.setDefaults({ cache: false }); 
      } 
      app.set('views', config.root + '/app/views/pages'); 
      app.set('view engine', 'html'); 

```

这样我们就可以在应用程序模板中使用`.html`文件扩展名。

### 创建部分文件

现在是时候创建部分文件本身了：

1.  从`app/views/partials`中打开`head.html`并添加以下代码：

```js
      <head> 
        <meta charset="UTF-8"> 
        <meta name="viewport" content="width=device-width"> 
        <title>{{ title }}</title> 
        <!--Let browser know website is optimized for mobile--> 
        <meta name="viewport" content="width=device-width, initial-scale=
           1.0"/> 
        <!-- Import Google Material font and icons --> 
        <link href="https://fonts.googleapis.com/icon?family=
          Material+Icons" rel="stylesheet"> 
        <!-- Compiled and minified CSS --> 
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax
          /libs/materialize/0.97.6/css/materialize.min.css"> 
        <link rel="stylesheet" href="/css/style.css"> 
        <!--Import jQuery before materialize.js--> 
        <script type="text/javascript" src="https://code.jquery.com/
           jquery-2.1.1.min.js"></script> 
        <!-- Compiled and minified JavaScript --> 
        <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize
          /0.97.6/js/materialize.min.js"></script> 
        <!-- Google Maps API to track location  --> 
        <scriptsrc="https://maps.googleapis.com/maps/api/js?key=<YOUR
          API KEY GOES HERE>"></script> 
      </head> 

```

### 提示

请注意，我们已经包含了一个名为`materialize.css`的`CSS`框架和 Google 地图 API 链接：<script src="img/js?key=<YOUR API KEY GOES HERE>"></script>

1.  从`app/views/partials`打开`footer.html`并添加以下代码：

```js
      <footer class="page-footer teal darken-1"> 
      <div class="container"> 
        <div class="row"> 
          <div class="col l6s12"> 
            <h5 class="white-text">Some Text Example</h5> 
            <p class="grey-text text-lighten-4">Lorem ipsum dolor
              sit amet, consecteturadipiscingelit, sed do 
              eiusmodtemporincididuntutlabore et dolore magna aliqua.
              Utenim ad minim veniam, quisnostrud 
              exercitationullamcolaboris nisi utaliquip ex
              eacommodoconsequat. Duisauteirure dolor in reprehenderit
              in voluptatevelitessecillumdoloreeufugiatnullapariatur.</p> 
          </div> 
          <div class="col l3s12"> 
            <h5 class="white-text">Sample Links</h5> 
            <ul> 
              <li><a class="white-text" href="#!">Link 1</a></li> 
              <li><a class="white-text" href="#!">Link 2</a></li> 
              <li><a class="white-text" href="#!">Link 3</a></li> 
              <li><a class="white-text" href="#!">Link 4</a></li> 
            </ul> 
          </div> 
          <div class="col l3s12"> 
            <h5 class="white-text">Sample Links</h5> 
            <ul> 
              <li><a class="white-text" href="#!">Link 1</a></li> 
              <li><a class="white-text" href="#!">Link 2</a></li> 
              <li><a class="white-text" href="#!">Link 3</a></li> 
              <li><a class="white-text" href="#!">Link 4</a></li> 
            </ul> 
          </div> 
        </div>
      </div> 
      <div class="footer-copyright"> 
      <div class="container"> 
        MVC Express App for: <a class="white-text text-darken-2"
        href="#">Node.js 6 Blueprints Book</a>
      </div> 
      </div> 
      </footer> 
      <!-- Live reload for development --> 
        {% if ENV_DEVELOPMENT %} 
          <scriptsrc="img/livereload.js"></script> 
        {% endif %} 
      <!--InitRsponsiveSidenav Menu  --> 
      <script> 
            (function ($) { 
              $(function () { 
                  $('.button-collapse').sideNav(); 
              }); 
            })(jQuery); 
      </script> 

```

### 创建应用程序模板文件

现在我们将替换`generator`创建的模板文件的内容：

1.  打开`app/views/pages/`中的`index.html`并添加以下代码：

```js
      {% extends 'layout.html' %} 
      {% block content %}
      <div id="map" style="height: 300px"></div> 
        <div class="section"> 
          <div class="container"> 
          <br> 
            <h1 class="header center teal-text">{{ title }}</h1> 
            <div class="row center"> 
              <h5 class="header col s12 light">Welcome to {{ title }}
              </h5> 
            </div> 
            <div class="row center"> 
              <a href="locations/add" id="download-button"
                class="btn-large waves-effect waves-light teal">
                Add your location
             </a> 
            </div> 
             <br><br> 
          </div> 
        </div> 
         <!-- Tracking current user position --> 
         <scriptsrc="img/getCurrentPosition.js"></script> 
         {% endblock %} 

```

### 提示

请注意`getCurrentPosition.js`文件添加到`index.html`模板中。在本章的后面，我们将解释这个文件发生了什么。

1.  打开`app/views/pages/`中的`layout.html`并添加以下代码：

```js
      <!doctype html> 
      <html lang="en"> 
      {% include "../partials/head.html" %} 
      <body> 
        <nav class="teal" role="navigation"> 
        <div class="nav-wrapper container"><a id="logo-container"
          href="/" class="brand-logo">Logo</a> 
          <ul class="right hide-on-med-and-down"> 
            <li><a href="/locations">Locations</a></li> 
            <li><a href="/locations/add">Add Location</a></li> 
            <li><a href="/stores">Stores</a></li> 
          </ul> 
          <ul id="nav-mobile" class="side-nav" style="transform:
            translateX(-100%);"> 
            <li><a href="/locations">Locations</a></li> 
            <li><a href="/locations/add">Add Location</a></li> 
            <li><a href="/stores">Stores</a></li> 
          </ul> 
          <a href="#" data-activates="nav-mobile" class="button-
           collapse"><i class="material-icons">menu</i></a> 
        </div> 
      </nav> 
      {% block content %}{% endblock %} 
       <!-- Footer --> 
       {% include "../partials/footer.html" %} 
      </body> 
      </html> 
```

1.  打开`app/views/pages/`中的`error.html`并添加以下代码：

```js
      {% extends 'layout.html' %} 
      {% block content %} 
      <div class="section"> 
        <div class="container"> 
        <br> 
          <h1 class="header center teal-text">{{ message }}</h1> 
          <div class="row center"> 
            <h3 class="header col s12 light">{{ error.status }}</h3> 
          </div> 
          <div class="row center"> 
            <pre>{{ error.stack }}</pre> 
          </div> 
          <br><br> 
        </div> 
      </div> 
      {% endblock %} 

```

现在我们有了开始应用程序开发所需的基线，但我们需要设置`getCurrentPosition.js`文件。

# 使用 Geolocation HTML5 API

我们可以使用各种资源来获取用户的位置，所以在这个例子中我们使用了**HTML5 API**。我们将使用外部 JavaScript 文件来创建一个显示用户精确位置的地图：

1.  创建一个名为`getCurrentPosition.js`的文件，并将其保存在`public/js`文件夹中。

1.  将以下代码放入`getCurrentPosition.js`中：

```js
      function getCurrentPosition() { 
          // Check boreswer/navigator support 
      if (navigator.geolocation) { 
      var options = { 
        enableHighAccuracy : true, 
        timeout : Infinity, 
        maximumAge : 0 
      }; 
        navigator.geolocation.watchPosition(getUserPosition, trackError,
        options); 
      }
      else { 
        alert('Ops; Geolocation is not supported'); 
      } 
         // Get user position and place a icon on map 
      function getUserPosition(position) { 
            // Check longitude and latitude 
      console.log(position.coords.latitude); 
      console.log(position.coords.longitude); 
            // Create the user' coordinates 
      var googlePos = new google.maps.LatLng(position.coords.latitude,
      position.coords.longitude); 
      var mapOptions = { 
        zoom : 12,
        center :googlePos, 
        mapTypeId :google.maps.MapTypeId.ROADMAP 
      }; 
        // Set a variable to get the HTML div 
        var mapObj = document.getElementById('map'); 
        // Create the map and passing: map div and map options 
        var googleMap = new google.maps.Map(mapObj, mapOptions); 
        // Setup a marker on map with user' location 
        var markerOption = { 
          map :googleMap, 
          position :googlePos, 
          animation :google.maps.Animation.DROP 
        }; 
      // Create a instance with marker on map 
        var googleMarker = new google.maps.Marker(markerOption); 
        // Get the user's complete address information using the Geocoder
        //Google API 
        var geocoder = new google.maps.Geocoder(); 
          geocoder.geocode({ 
             'latLng' : googlePos 
          },
          function(results, status) { 
            if (status == google.maps.GeocoderStatus.OK) { 
              if (results[1]) { 
                var popOpts = { 
                content : results[1].formatted_address, 
                position :googlePos 
                }; 
                // Setup an info window with user information 
                var popup = new google.maps.InfoWindow(popOpts); 
                google.maps.event.addListener(googleMarker,
                'click', function() { 
                   popup.open(googleMap); 
                 }); 
              }
              else { 
                alert('No results found'); 
              } 
            }
            else { 
             alert('Uhh, failed: ' + status); 
            } 
          }); 
        } 
        // Setup a error function 
        function trackError(error) { 
        var err = document.getElementById('map'); 
         switch(error.code) { 
         case error.PERMISSION_DENIED: 
         err.innerHTML = "User denied Geolocation."; 
         break; 
         case error.POSITION_UNAVAILABLE: 
         err.innerHTML = "Information is unavailable."; 
         break; 
         case error.TIMEOUT: 
         err.innerHTML = "Location timed out."; 
         break; 
         case error.UNKNOWN_ERROR: 
         err.innerHTML = "An unknown error."; 
         break; 
        } 
        }
      } 
      getCurrentPosition(); 

```

因此，当我们转到`http://localhost:3000/`时，我们可以在地图上看到我们的地址指出，就像以下屏幕截图中一样：

![使用 Geolocation HTML5 API](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_002.jpg)

启用地理定位的主屏幕

### 提示

请注意，您的浏览器将请求权限以跟踪您的位置

# 创建应用程序控制器

现在的下一步是创建应用程序控制器：

1.  在`app/controllers/`文件夹中创建一个名为`locations.js`的新文件，并添加以下代码：

```js
      var express = require('express'), 
      router = express.Router(), 
      mongoose = require('mongoose'), 
      Location = mongoose.model('Location'); 
      module.exports = function (app) { 
      app.use('/', router); 
      }; 
      router.get('/locations', function (req, res, next) { 
      Location.find(function (err, item) { 
      if (err) return next(err); 
        res.render('locations', { 
          title: 'Locations', 
          location: item, 
          lat: -23.54312, 
          long: -46.642748 
        }); 
        //res.json(item); 
          }); 
      }); 
      router.get('/locations/add', function (req, res, next) { 
      res.render('add-location', { 
      title: 'Insert Locations' 
          }); 
      }); 
      router.post('/locations', function (req, res, next) { 
          // Fill loc object with request body 
      varloc = {
        title: req.body.title, 
        coordinates: [req.body.long, req.body.lat] 
      }; 
      var locations = new Location(loc); 
      // save the data received 
       locations.save(function(error, item) { 
       if (error) { 
         returnres.status(400).send({ 
         message: error 
         }); 
       } 
        //res.json({message: 'Success', obj: item}); 
         res.render('add-location', { 
         message: 'Upload with Success', 
         obj: item 
              }); 
          }); 
      });  

```

请注意，我们放置了一个固定的位置来居中地图，并创建了 3 条路线：

+   `router.get('/locations',...);`以从 MongoDB 获取所有位置

+   `router.get('/locations/add',...);`以呈现添加位置表单

+   `router.post('/locations',...);`以将新位置添加到 MongoDB

另一个重要的要点是`get(/locations)`上的注释代码：

```js
 //res.status(200).json(stores);.

```

这样我们可以返回一个纯 JSON 对象，而不是使用变量渲染模板。

# 创建模型

现在让我们创建我们的模型来保存位置数据：

在`app/models`文件夹中，创建一个名为`locations.js`的文件，并添加以下代码：

```js
      // Example model 
      var mongoose = require('mongoose'), 
        Schema = mongoose.Schema; 
      varLocationSchema = new Schema({ 
        title: String, 
        coordinates: { 
          type: [Number], 
          index: '2dsphere' 
        },  
        created: { 
          type: Date, 
          default: Date.now 
        } 
      }); 
      mongoose.model('Location', LocationSchema);  

```

重要的是注意前一个代码中坐标属性的数据类型和 2dsphere 的索引。

### 提示

您可以在 MongoDB 的官方文档中阅读有关 2dsphere 的更多信息：[`docs.mongodb.com/manual/core/2dsphere/`](https://docs.mongodb.com/manual/core/2dsphere/)。

# 创建视图模板

现在让我们创建`view`文件。这个文件对我们的应用程序非常重要，因为这是我们将`Swig`变量资源与我们的 JavaScript 代码集成的地方：

1.  创建一个名为`locations.html`的文件，并将其保存在`app/views/pages/`文件夹中。

1.  将以下代码放入`locations.html`文件中：

```js
      {% extends 'layout.html' %} 
      {% block content %} 
      <div class="section"> 
        <div class="container"> 
        <br><br> 
          <h1 class="header center teal-text">{{ title }}</h1> 
          <div class="row center"> 
            <h5 class="header col s12 light">Welcome to 
              {{ title }}
            </h5> 
          </div> 
          <div class="row"> 
            <div class="col s12"> 
            <form action="/nearme" method="POST"> 
              <div class="row"> 
                <div class="col s12" id="map" style="height:600px;
                 width: 100%; margin-bottom: 20px"></div> 
                <br> 
                  <h5 class="grey-text center"> 
                            Find a store near by you 
                   </h5> 
                 <br> 
                 <div class="input-field col s5"> 
                   <input placeholder="Insert Longitude"
                    name="longitude" id="longitude" type="text"
                    class="validate" value="{{long}}">
                   <label for="longitude">Longitude</label> 
                 </div> 
                 <div class="input-field col s5"> 
                 <input placeholder="Insert latitude" name="latitude"
                   id="latitude" type="text" class="validate"
                   value="{{lat}}"> 
                 <label for="latitude">Latitude</label> 
                 </div> 
                 <div class="input-field col s2"> 
                   <select class="browser-default" name="distance"
                    id="distance">
                     <option value="" disabled selected>Distance
                     </option>
                     <option value="2">2 Km</option> 
                     <option value="3">3 km</option> 
                     <option value="9">9 km</option> 
                   </select> 
                 </div> 
               </div> 
               <div class="row"> 
               <button class="btn waves-effect waves-light"
                 type="submit" name="action">SUBMIT</button> 
               </div> 
             </form> 
             <br> 
           </div> 
         </div> 
       </div> 
       </div> 

```

上一个代码非常简单；我们只有一个空的`map` div：

```js
 <div class="col s12" id="map" style="height: 600px; width: 100%;
        margin-bottom: 20px"></div> 

```

我们还有一个简单的表单，使用`POST`方法根据纬度和经度查找最近的位置：

```js
 <form action="/nearme" method="POST">

```

![创建视图模板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_003.jpg)

locations.html 的屏幕截图

接下来最重要的代码是：

1.  在`locations.html`文件的末尾添加以下代码：

```js
      <script type="text/javascript"> 
      var loadMap = function() { 
          // Center map with current lat and long (Simulated with fixed
            point for this example) 
         var googlePos = new google.maps.LatLng({{ lat }} , {{ long }}); 
          // Setup map options 
         var mapOptions = { 
           zoom : 12, 
           center :googlePos, 
           mapTypeId :google.maps.MapTypeId.ROADMAP 
         }; 
        // Set a variable to get the HTML div 
        var mapObj = document.getElementById('map'); 
        var googleMap = new google.maps.Map(mapObj, mapOptions); 
         // Create markers array to hold all markers on map 
        var markers = []; 
        // Using the Swig loop to get all data from location variable 
        {% for item in location %} 
            // Setup a lat long object 
          var latLng = new google.maps.LatLng({{ item.coordinates[1] }},
           {{ item.coordinates[0] }}); 
            // Create a marker 
          var marker = new google.maps.Marker({ 
            map :googleMap, 
            position: latLng, 
            animation :google.maps.Animation.DROP 
          }); 
          markers.push(marker); 
            // Setup the info window 
          varinfowindow = new google.maps.InfoWindow(); 
            // Add an event listener to click on each marker and show
               an info window 
          google.maps.event.addListener(marker, 'click', function () { 
          // using the tittle from the Swig looping 
            infowindow.setContent('<p>' + " {{ item.title }} " + '</p>'); 
            infowindow.open(googleMap, this); 
          }); 
          {% endfor %} 
        }; 
       // load the map function 
       window.onload = loadMap; 
       </script> 
       {% endblock %} 

```

这段代码片段做了很多事情，包括创建一个新的地图对象：

```js
      varmapObj = document.getElementById('map'); 
      vargoogleMap = new google.maps.Map(mapObj, mapOptions); 

```

它还添加了来自 MongoDB 并位于位置对象循环内的标记或点：

```js
      {% for item in location %} 
         ... 
      {% endfor %}

```

您可以看到上一个代码的每一行都有一个注释；这样很容易理解每一行发生了什么。

1.  让我们创建一个新文件。创建一个名为`add-location.html`的文件，并将其保存在`app/views/pages/`文件夹中。

1.  将以下代码放入`add-location.html`文件中：

```js
      {% extends 'layout.html' %} 
      {% block content %} 
      <div class="section"> 
        <div class="container"> 
        <br><br> 
          <h1 class="header center teal-text">{{ title }}</h1> 
          <div class="row center"> 
            <h5 class="header col s12 light">Welcome to 
             {{ title }}
            </h5> 
          </div> 
          <div class="row"> 
            <div class="col s12"> 
                {% if message %} 
                  <h4 class="center teal-text"> 
                        {{ message }} 
                  </h4> 
                {% endif %} 
                <h5 class="grey-text"> 
                      Insert a new location 
                </h5> 
                <br> 
                <form action="/locations" method="POST"> 
                  <div class="row"> 
                  <div class="input-field col s4"> 
                    <input placeholder="Insert Location Title"
                     name="title" id="title" type="text" class="validate"> 
                    <label for="title">Title</label> 
                    </div> 
                    <div class="input-field col s4"> 
                      <input placeholder="Insert Longitude"
                       name="long" id="long" type="text" class="validate"> 
                      <label for="long">Longitude</label> 
                    </div>  
                    <div class="input-field col s4"> 
                    <input placeholder="Insert lat" name="lat" id="lat" 
                     type="text" class="validate"> 
                    <label for="lat">Latitude</label> 
                    </div> 
                      <br> 
                      <br> 
                    <div class="col s12 center"> 
                    <button class="btn waves-effect waves-light" 
                     type="submit" name="action">SUBMIT</button> 
                    </div> 
                  </div> 
                </form> 
                </div> 
              </div> 
            </div> 
          </div> 
          {% endblock %} 

```

这是一个简单的表单，用于将一些位置添加到 MongoDB，并且将看起来像以下屏幕截图：

![创建视图模板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_004.jpg)

add-location.html 的屏幕截图

# 将位置添加到 MongoDB

现在是我们应用程序的有趣部分。我们需要在我们的应用程序中插入记录；出于教学目的，我们将使用表单（`add-location.html`）逐个插入记录。

该示例展示了如何插入一条记录，您应该对其他记录执行相同的操作。

### 提示

您可以跳过这一步，加载填充数据库的示例文件，但我们建议您按照本书中的步骤进行操作。

在本示例结束时，我们将解释如何使用 RoboMongo 面板一次加载所有记录。

1.  在项目根文件夹打开终端/Shell，并输入以下命令：

```js
gulp

```

### 提示

请注意，在执行上述操作之前，您必须确保您的 MongoDB 已经启动。

1.  转到`http://localhost:3000/locations/add`，并填写以下信息的表单：

### 提示

请注意，您也需要将地图中心设置为您自己的位置，在`locations.js`控制器的纬度和经度属性上：

```js
router.get('/locations', function (req, res, next) {
Location.find(function (err, item) {
...
res.render('locations', {
...
lat: -23.54312,
long: -46.642748
});
});
});

```

标题 = **Republica**

经度 = **-46.642748**

纬度 = **-23.54312**

点击**提交**按钮，您将在地图上方看到一个成功消息。

1.  现在我们将使用 RoboMongo 界面添加接下来的七个位置。复制以下代码：

```js
      db.locations.insert( 
      [{ 
          "title": "Mackenzie", 
          "coordinates": [-46.651659, -23.54807] 
      }, { 
          "title": "Shopping Maia B", 
          "coordinates": [-46.539545, -23.44375] 
      }, { 
          "title": "MorumbiSaraiva", 
          "coordinates": [-46.699053, -23.62376] 
      }, { 
          "title": "Shopping Center Norte", 
          "coordinates": [-46.617417, -23.51575] 
      }, { 
          "title": "Mooca Plaza Shopping", 
          "coordinates": [-46.594408, -23.57983] 
      }, { 
          "title": "Shopping Metro Tucuruvi", 
          "coordinates": [-46.602695, -23.47984] 
      }, { 
          "title": "Market Place", 
          "coordinates": [-46.696713, -23.61645] 
      }] 
      ) 

```

1.  在 RoboMongo 界面上，选择左侧面板上的 maps-api-development 数据库。

1.  将代码粘贴到 RoboMongo 界面中：![将位置添加到 MongoDB](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_005.jpg)

RoboMongo 界面终端的截图

1.  让我们来检查结果：双击左侧菜单上的**locations**集合。

1.  在 RoboMongo 视图的右侧，点击**以表格模式查看结果**；您将看到以下结果：![将位置添加到 MongoDB](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_006.jpg)

RoboMongo 面板的截图

此时，我们已经在 http://localhost:3000/locations 的地图上有了所有位置，但是附近商店的查找表单仍然无法工作，因此我们需要设置一个 MongoDB 2dsphere 索引。

# 了解 MongoDB 上的地理空间索引

从 MongoDB 的*2.4*版本开始，我们可以使用**GeoJSON**格式进行地理空间搜索。

### 提示

您可以在官方链接处找到有关 GeoJSON 的更多信息：[`geojson.org/`](http://geojson.org/)。

**GeoJSON**是一个用于格式化坐标形状的开源规范。它被广泛使用，并且非常适用于使用地理数据制作应用程序。这种格式非常简单，我们在位置模型中使用了这种格式，正如您所看到的：

```js
var LocationSchema = new Schema({ 
  title: String, 
  coordinates: { 
    type: [Number], 
    index: '2dsphere' 
  }, 
  created: { 
    type: Date, 
    default: Date.now 
  } 
}); 

```

突出显示的代码是用于存储坐标的 GeoJSON 格式。

### 提示

您可以在这里阅读更多关于 MongoDB 上的地理空间查询：[`docs.mongodb.com/manual/reference/operator/query-geospatial/`](https://docs.mongodb.com/manual/reference/operator/query-geospatial/)，以及更多地理空间索引信息：[`docs.mongodb.com/manual/applications/geospatial-indexes/`](https://docs.mongodb.com/manual/applications/geospatial-indexes/)。

## 在 MongoDB 中创建 2dsphere 索引

让我们在 MongoDB 中检查我们的位置集合：

1.  打开你的 RoboMongo，并在左侧面板上选择**maps-api-development**数据库。

1.  双击**locations**集合，您将看到以下数据：![在 MongoDB 中创建 2dsphere 索引](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_007.jpg)

索引之前的位置集合截图

您会注意到我们只有一个带有**id**索引的文件夹；这是 MongoDB 的默认设置。

1.  复制以下代码并粘贴到 RoboMongo 界面中：

```js
db.locations.ensureIndex({ 'coordinates' : '2dsphere'})

```

1.  点击右上角菜单栏中的**播放**按钮。

结果将如下截图所示：

![在 MongoDB 中创建 2dsphere 索引](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_008.jpg)

ensure.index()后的截图

请注意，现在我们已经创建了 2dsphere 索引。

# 检查地理位置应用

现在是测试应用程序的时候了。我们已经在我们的数据库中创建了八条记录，已经使用 ensure.index() MongoDB 对所有位置进行了索引，我们已经可以在地图中看到所有点的渲染，就像下面的截图中所看到的那样：

![检查地理位置应用](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_009.jpg)

locations.html 的截图

在上一个屏幕截图中，您可能会注意到地图上的点彼此之间相距较远，这能够显示当我们改变距离搜索字段时所显示的点之间的距离差异。

在这个例子中，我们可以在搜索栏中插入任何纬度和经度，但我们只是固定这个字段来说明应用程序的地理定位功能。

当我们首次访问位置路由时，我们会显示数据库中的所有记录，就像我们在上一个屏幕截图中看到的那样。

让我们改变 locations.html 表单上的距离，看看会发生什么；转到 http://localhost:3000/locations，在**距离**字段中选择*2km*，然后点击**提交**按钮。

在 MongoDB 中使用$near 和$geometry 函数进行新查询的结果将如下所示：

![检查地理定位应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_010.jpg)

通过 2km 筛选的位置页面的屏幕截图

这对于商店定位应用程序来说是非常有用的信息，但我们无法看到我们正在寻找的最近点在哪里。为了方便查看，我们将在地图上的左侧添加一个点列表，按从最近到最远的顺序列出。

# 按距离排序点

让我们添加一些代码行，使我们的搜索更直观：

1.  在 app/views/pages/locations.html 中添加以下行，在突出显示的代码之间：

```js
 <div class="row">      <div class="col s3"> 
              ... 
 </div> <div class="col s9"> <form action="/nearme" method="POST">           ... 
     </div> 
     </div> 

```

### 提示

请注意，您可以在 Packt Publishing 网站或本书的官方 GitHub 存储库上下载完整的代码。

1.  在{% endfor %}循环之后，在 locations.html 的末尾添加以下函数：

```js
      // get all the pan-to-marker class 
      var els = document.querySelectorAll(".pan-to-marker"); 
      // looping over all list elements 
      for (vari = 0, len = els.length; i<len; i++) { 
        els[i].addEventListener("click", function(e){ 
          e.preventDefault(); 
     // Use -1 for index because loop.index from swig starts on 1 
     var attr = this.getAttribute('data-marker-index') -1; 
        // get longitude and latitude of the marker 
       var latitude = markers[attr].getPosition().lat(); 
       var longitude = markers[attr].getPosition().lng(); 
        console.log(latitude, longitude ); 
          // Center map and apply zoom 
           googleMap.setCenter({lat: latitude, lng: longitude}); 
           googleMap.setZoom(18); 
           }); 
      } 

```

现在当我们返回到位置页面时，我们可以看到地图左侧按距离排序的点列表。请参阅下面的屏幕截图：

![按距离排序点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_011.jpg)

左侧商店列表的屏幕截图

现在我们可以点击左侧面板上的任何商店。我们还可以放大地图，如下面的屏幕截图所示：

![按距离排序点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_05_012.jpg)

选定商店的 locations.html 屏幕截图

# 摘要

在本章中，我们涵盖了许多与 Google Maps API 和 MongoDB 上的地理空间查询相关的内容，并使用 Node.js 和一些默认的 Express 模块构建了一个完整的商店定位器应用程序。

我们涵盖了诸如 GeoJSON 文件格式以及如何在 MongoDB 上创建地理空间索引等重要内容。

本章结束了涵盖使用不同模板引擎和技术的 MVC 设计模式的五章系列。在下一章中，我们将看到如何使用一些不同的工具来创建和测试 API，构建一个 Node.js API。


# 第六章：使用 Restful API 和 Loopback.io 构建客户反馈应用程序

如前所述，Node.js 生态系统有各种框架用于开发强大的 Web 应用程序。在之前的章节中，我们使用了最流行的 Express 框架。

在本章中，我们将探索另一个名为 loopback.io 的框架。该框架在很大程度上基于 Express，但它为我们提供了一些更多的功能，可以快速创建 Restful API。

它有一个**命令行界面**（**CLI**），可以在不使用代码的情况下创建 API，还公开了一个用于操作 HTTP 动词的接口，一种嵌入在应用程序中的 Restful 客户端，以及其他一些优势。

我们还将看到如何使用 React.js 库在我们的应用程序前端消耗此 API。

在本章中，我们将涵盖以下主题：

+   安装 LoopBack 框架

+   LoopBack CLI 的基础知识

+   使用命令行创建模型

+   处理数据源和数据库关系

+   创建一个简单的 React.js 应用程序来消耗 API

# 我们正在构建什么

在本章中，我们将构建一个 API 来存储任何类型的产品，例如经典的摩托车模型，并存储用户对该摩托车的评论/反馈。结果将看起来像以下屏幕截图：

![我们正在构建什么](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_001.jpg)

主页的屏幕截图

## 创建基线结构

首先让我们安装 LoopBack 框架：

1.  打开您的终端/Shell 并键入以下命令：

```js
npm install strongloop -g

```

1.  打开您的终端/Shell 并键入以下命令：

```js
slc loopback

```

1.  输入名称：目录选项为 chapter-06。

1.  选择 empty-server（一个没有任何内容的 LoopBack API）

配置模型或数据源）选项。

不要担心输出的结尾，我们将在下一个主题中解释这一点。

结果将是以下文件夹和文件的结构：

![创建基线结构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_002.jpg)

文件夹和文件的屏幕截图

结构非常简单；几乎所有 LoopBack 的配置都在 JSON 文件中，如**component-config.json**，**config.json**，**datasources.json**，以及**server**文件夹中的所有其他文件。

### 提示

您可以通过在终端窗口中键入以下命令来了解有关**slc**命令行的更多信息：slc -help。

# 使用命令行创建模型

此时，我们已经有了开始开发 API 所需的结构。

现在我们将使用命令行来创建应用程序的模型。我们将构建两个模型：一个用于产品/摩托车，另一个用于用户/消费者。

1.  在 chapter-06 文件夹中打开终端/Shell 并键入以下命令：

```js
slc loopback:model

```

1.  填写摩托车模型的以下信息，如下图所示：![使用命令行创建模型](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_003.jpg)

创建摩托车模型后的终端输出的屏幕截图

1.  填写属性名称：

```js
      Property name: image
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: make
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: description
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: model
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: category
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: year
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:
```

1.  让我们创建客户模型。打开终端/Shell 并键入以下命令：

```js
slc loopback:model

```

1.  填写审查模型的信息，如下图所示：![使用命令行创建模型](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_004.jpg)

创建模型审查后的终端输出的屏幕截图

1.  填写属性名称：

```js
      Property name: name
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: email
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

      Property name: review
      ? Property type: string
      ? Required? Yes
      ? Default value[leave blank for none]:

```

即使使用命令行，我们也可以检查和编辑刚刚创建的模型。

### 提示

这里需要注意的一个重要点是，common 属性创建一个目录并与 client 和 server 文件夹共享。如果使用 server 属性，代码将存储在 server 文件夹中，并且不与 client 文件夹共享。

# 使用命令行创建模型后编辑模型

我们可以直接在 common/models/文件夹中编辑模型。我们为每个创建的模型有两个文件。

第一个是一个带有所有属性的 JSON 文件，如我们在 review.json 文件中所见的代码：

```js
    { 
      "name": "review", 
      "base": "PersistedModel", 
      "idInjection": true, 
      "options": { 
        "validateUpsert": true 
      }, 
      "properties": { 
        "name": { 
        "type": "string", 
        "required": true 
      }, 
      "email": { 
        "type": "string", 
        "required": true 
      }, 
      "review": { 
          "type": "string", 
          "required": true 
      } 
    }, 
      "validations": [], 
      "relations": {}, 
      "acls": [], 
      "methods": {} 
    } 

```

第二个是一个 JavaScript 文件，如我们在 review.js 文件中所见的代码：

```js
    module.exports = function(Review) { 
    }; 

```

JavaScript 文件是您可以配置应用程序方法的地方。您可能会注意到，在创建模型时，其功能是空的；这是因为 LoopBack 框架通过使用 Express 框架来抽象常见的 CRUD 操作，这与我们在上一章中所做的操作相同。

# 通过命令行创建数据源

我们将使用数据库存储客户的反馈，因此我们将使用 LoopBack CLI 创建数据源：

1.  在根项目中打开终端/ shell 并输入以下命令：

```js
slc loopback:datasource

```

1.  使用以下信息填写选项：![通过命令行创建数据源](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_005.jpg)

数据源终端输出的屏幕截图

请注意，最终选项是安装 MongoDB 连接器。因此，请不要忘记在 MongoDB 实例上创建数据库：motorcycle-feedback。

### 提示

在本书示例中，我们不使用数据库的用户名和密码，但强烈建议您在生产环境中使用用户名和强密码。

数据源配置可以在 server/datasources.json 文件中找到，如下代码所示：

```js
    { 
      "motorcycleDataSource": { 
        "host": "localhost", 
        "port": 27017, 
        "database": "motorcycle-feedback", 
        "password": "", 
        "name": "motorcycleDataSource", 
        "user": "", 
        "connector": "mongodb" 
      } 
    } 

```

Loopback API 为我们提供了在不同数据库上配置数据源的可能性。

# 将模型连接到数据源

下一步是建立模型和数据源之间的关系，为此我们将手动编辑文件。

请记住，命令行也提供了此功能，使用 slc loopback:relation:，但是在撰写本文时，生成器中存在错误，我们目前无法使用此功能。但是，这并不妨碍我们继续进行应用程序开发，因为命令行工具并非强制使用：

打开 server/model-config.json 并添加以下突出显示的代码：

```js
      { 
        "_meta": { 
          "sources": [ 
            "loopback/common/models", 
            "loopback/server/models", 
            "../common/models", 
            "./models" 
          ], 
          "mixins": [ 
            "loopback/common/mixins", 
            "loopback/server/mixins", 
            "../common/mixins", 
            "./mixins" 
          ] 
        }, 
        "motorcycle": { 
          "dataSource": "motorcycleDataSource", 
          "public": true 
        }, 
        "review": { 
          "dataSource": "motorcycleDataSource", 
          "public": true 
        } 
      } 

```

在这个阶段，通常会使用称为 ARC 工具的可视界面来构建、部署和管理我们的 Node API，但是对于本书的示例，我们不会使用它，因此将所有注意力都集中在代码上。

### 提示

您可以在此链接找到有关 ARC 的更多信息：[`docs.strongloop.com/display/APIS/Using+Arc`](https://docs.strongloop.com/display/APIS/Using+Arc)。

# 使用 API Explorer

LoopBack API Explorer 最好的功能之一是生成一个本地主机 API 端点，允许我们查看和测试 API 生成的所有端点。

此外，它可能值得作为文档，包含所有必要的指令，如 HTTP 动词 GET、POST、UPDATE、DELETE，如果需要发送令牌访问，数据类型和 JSON 格式。

1.  打开终端/ shell 并输入以下命令：

```js
npm start 

```

1.  转到 http://localhost:3000/explorer/#/。结果将是以下屏幕截图：![使用 API Explorer](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_006.jpg)

API Explorer 的屏幕截图

可以看到 API 基本 URL 和 API 版本，我们的项目名称和应用程序端点。

1.  当我们点击**review**模型时，我们可以看到所有带有 HTTP 动词的端点，如下图所示：![使用 API Explorer](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_007.jpg)

评论端点和 HTTP 动词的屏幕截图

创建的端点如下：

+   http://localhost:3000/api/reviews

+   http://localhost:3000/api/motorcycles

当然，您也可以直接使用浏览器访问它们。

重要的是要注意 GET 和 POST 端点是相同的，区别在于：当我们想要检索内容时，我们使用 GET 方法，当我们想要插入内容时，我们使用 POST 方法，PUT 和 DELETE 也是一样，我们需要在 URL 的末尾传递 ID，如 http://localhost:3000/api/reviews/23214。

我们还可以看到每个端点右侧有一个简要描述其目的的描述。

它还具有一些其他非常有用的端点，如下图所示：

![使用 API Explorer](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_008.jpg)

评论端点的附加方法的屏幕截图

## 使用端点插入记录

现在我们将使用 API Explorer 界面向数据库中插入一条记录。我们将插入一个产品，即我们的摩托车：

1.  转到 http://localhost:3000/explorer/#!/motorcycle/motorcycle_create。

1.  将以下内容放入数据值字段中，然后点击“尝试一下”按钮：

```js
      { 
         "make": "Harley Davidson", 
         "image": "images/heritage.jpg", 
         "model": "Heritage Softail", 
         "description": "An Evolution V-twin Engine!", 
         "category": "Cruiser", 
         "year": "1986" 
      } 

```

响应主体将如下截图所示：

![使用端点插入记录](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_009.jpg)

POST 成功的屏幕截图

请注意，我们有一个 HTTP 状态码**200**和一个新创建数据的 ID。

## 使用端点检索记录

现在我们将使用 API Explorer 界面从数据库中检索记录。我们将使用摩托车端点：

1.  转到 http://localhost:3000/explorer/#!/motorcycle/motorcycle_find。

1.  单击“尝试一下”按钮，我们将得到与之前截图相同的结果。

请注意，我们正在使用 API 资源管理器，但我们所有的 API 端点都通过 http://localhost:3000/api/公开。

1.  转到 http://localhost:3000/api/motorcycles，您可以在浏览器上看到以下结果：![使用端点检索记录](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_010.jpg)

摩托车端点的屏幕截图

### 提示

请注意，我们正在使用一个名为**JSON VIEW**的 Chrome 扩展程序，您可以在这里获取：[`chrome.google.com/webstore/detail/jsonview/chklaanhfefbnpoihckbnefhakgolnmc`](https://chrome.google.com/webstore/detail/jsonview/chklaanhfefbnpoihckbnefhakgolnmc)。

在处理大型 JSON 文件时非常有用。

# 添加数据库关系

现在我们已经配置了端点，我们需要在应用程序模型之间创建关系。

我们的反馈将被插入到特定类型的产品中，例如我们的摩托车示例，然后每个摩托车型号都可以接收各种反馈。让我们看看如何通过直接编辑源代码来创建模型之间的关系有多简单：

1.  打开 common/models/motorcycle.json 并添加以下突出显示的代码：

```js
      { 
          "name": "motorcycle", 
          "base": "PersistedModel", 
          "idInjection": true, 
          "options": { 
              "validateUpsert": true 
          }, 
          "properties": { 
            "image": { 
               "type": "string", 
               "required": true 
            }, 
            "make": { 
              "type": "string", 
              "required": true 
            }, 
            "description": { 
               "type": "string", 
               "required": true 
            }, 
            "model": { 
              "type": "string", 
              "required": true 
            }, 
            "category": { 
              "type": "string", 
              "required": true 
            }, 
            "year": { 
              "type": "string", 
              "required": true 
            } 
          }, 
          "validations": [], 
          "relations": { 
              "review": { 
                "type": "hasMany", 
                "model": "review", 
                "foreignKey": "ObjectId"
 } 
            }, 
            "acls": [], 
            "methods": {} 
      }

```

1.  重新启动应用程序，打开终端窗口，然后输入以下命令：

```js
npm start

```

1.  转到 http://localhost:3000/explorer。

我们可以看到 LoopBack 已经为这种关系创建了新的端点，如下图所示：

![添加数据库关系](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_011.jpg)

新端点创建的屏幕截图

现在我们可以使用以下方式获取与摩托车模型相关的所有反馈：

http://localhost:3000/api/motorcycles/<id>/review。

我们还可以通过简单地将评论 ID 添加到以下 URL 中来获取一个评论：

http://localhost:3000/api/motorcycles/<id>/review/<id>。

# 处理 LoopBack 引导文件

在使用 LoopBack 框架的应用程序中，引导文件非常重要。这些文件在应用程序执行时启动，并可以执行各种任务。

该应用程序已经具备了所有需要的端点。因此，让我们看看如何创建一个引导文件，并使用 LoopBack 框架的另一个功能来将我们的模型迁移到数据库。

在这个例子中，我们将看到如何使用 automigrate 函数在启动应用程序时向数据库中插入一些内容：

### 提示

您可以在[`apidocs.strongloop.com/`](http://apidocs.strongloop.com/)上阅读更多关于 LoopBack API 的信息。

在 server/boot 中，创建一个名为 create-sample-models.js 的新文件，并将以下内容放入其中：

```js
      module.exports = function(app) { 
          // automigrate for models, every time the app will running,
           db will be replaced with this data. 
         app.dataSources.motorcycleDataSource.automigrate('motorcycle',
          function(err) { 
          if (err) throw err; 
          // Simple function to create content 
            app.models.Motorcycle.create( 
              [ 
                { 
                  "make": "Harley Davidson", 
                  "image": "images/heritage.jpg", 
                  "model": "Heritage Softail", 
                  "description": "An Evolution V-twin Engine!", 
                  "category": "Cruiser", 
                  "year": "1986", 
                  "id": "57337088fabe969f2dd4078e" 
                } 
              ], function(err, motorcycles) { 
                  if (err) throw err; 
                 // Show a success msg on terminal 
                   console.log('Created Motorcycle Model: \n',
                    motorcycles); 
                  }); 
                }); 
                app.dataSources.motorcycleDataSource.automigrate
                 ('review', function(err) { 
                if (err) throw err; 
                // Simple function to create content 
                app.models.Review.create( 
                  [ 
                    { 
                      "name": "Jax Teller", 
                      "email": "jax@soa.com", 
                      "id": "57337b82e630a9152ed6554d", 
                      "review": "I love the Engine and sound", 
                      "ObjectId": "57337088fabe969f2dd4078e" 
                    }, 
                    { 
                      "name": "Filip Chibs Telford", 
                      "email": "chibs@soa.com", 
                      "review": "Emblematic motorcycle of the world", 
                      "id": "5733845b00f4a48b2edd54cd", 
                      "ObjectId": "57337088fabe969f2dd4078e" 
                    }, 
                    { 
                      "name": "Clay Morrow", 
                      "email": "clay@soa.com", 
                      "review": "A classic for the eighties, i love
                        the engine sound", 
                      "id": "5733845b00f4a48b2edd54ef", 
                      "ObjectId": "57337088fabe969f2dd4078e" 
                    } 
                  ], function(err, reviews) { 
                  if (err) throw err; 
                  // Show a success msg on terminal 
                   console.log('Created Review Model: \n', reviews); 
                  }); 
                }); 
              };  

```

上面的代码非常简单；我们只是使用模型的对象属性创建对象。现在，每次应用程序启动时，我们都会向数据库发送一条摩托车记录和三条摩托车反馈。

这一步完成了我们的 API。尽管这是一个非常琐碎的例子，但我们探索了 LoopBack 框架的几个强大功能。

此外，我们还可以使用 ARC 编辑器。正如前面提到的，只需使用图形界面就可以创建模型和迁移。它还非常有用，比如部署和其他用途。

# 使用 API

现在我们将探讨如何使用此 API。我们已经看到 API 包含在：localhost:3000/api/，我们的根路径只有一些关于 API 的信息，我们可以通过访问 localhost:3000 来查看：

```js
{
 started: "2016-05-15T15:20:24.779Z",
 uptime: 7.017
}

```

让我们更改 root.js 和 middleware.json 文件，并使用一些客户端库与 API 进行交互。

## 将 HTML 内容添加到客户端

1.  将 server/boot 中的 root.js 文件更改为 _root.js。

1.  打开 server/文件夹中的 middleware.json，并添加以下突出显示的代码：

```js
      { 
        "initial:before": { 
        "loopback#favicon": {} 
      }, 
        "initial": { 
          ... 
          }, 
          "helmet#xssFilter": {}, 
          "helmet#frameguard": { 
           ... 
          }, 
           "helmet#hsts": { 
            ... 
           }, 
           "helmet#hidePoweredBy": {}, 
          "helmet#ieNoOpen": {}, 
          "helmet#noSniff": {}, 
          "helmet#noCache": { 
            ... 
           } 
        }, 
        "session": {}, 
        "auth": {}, 
        "parse": {}, 
        "routes": { 
         ... 
          } 
        }, 
        "files": { 
           "loopback#static": { 
              "params": "$!../client" 
           } 
        }, 
        "final": { 
          "loopback#urlNotFound": {} 
        }, 
         "final:after": { 
            "loopback#errorHandler": {} 
        } 
      } 

```

1.  在 client 文件夹中创建一个名为 index.html 的新文件，并将其保存在 client 文件夹中。

现在我们配置应用程序以映射客户端文件夹并使其公开访问。这与我们为 Express 框架设置静态路由时非常相似。我们可以以其他方式设置应用程序的路由，但在此示例中，让我们保持这种方式。

## 添加 Bootstrap 框架和 React 库

现在让我们将依赖项添加到我们的 HTML 文件中；我们将使用 Bootstrap 和 React.js。

请注意，突出显示的文件是从**内容传送网络**（**CDN**）提供的，但如果您愿意，您可以将这些文件存储在 client 文件夹或用于 CSS 和 JavaScript 的子目录中：

1.  打开新创建的 index.html 文件，并添加以下代码：

```js
      <!DOCTYPE html> 
      <html> 
      <head><title>Motorcycle Customer feedback</title></head> 
      <link rel='stylesheet' href='https://cdnjs.cloudflare.com/
       ajax/lib/twitter-bootstrap/4.0.0-alpha/css/bootstrap.min.css'> 
      <style> 
        body { 
          padding-top: 5rem; 
        } 
        .starter-template { 
          padding: 3rem 1.5rem; 
          text-align: center; 
        } 
      </style> 
        <body> 
          <nav class="navbar navbar-fixed-top navbar-dark bg-inverse"> 
          <div class="container"> 
            <a class="navbar-brand" href="#">Custumer Feedback</a> 
            <ul class="nav navbar-nav"> 
              <li class="nav-item active"> 
                <a class="nav-link" href="#">Home <span class="sr-only">
                 (current)</span></a> 
              </li> 
            </ul> 
          </div> 
          </nav> 
          <div class="container"> 
            <!-- This element's contents will be replaced with 
              your component. --> 
          <div id="title"> 
            <div class="starter-template"> 
              <h1>Motorcycle Feedback</h1> 
              <p class="lead">Add your comments about this model.</p> 
            </div> 
          </div> 
          <div class="row"> 
            <div class="col-lg-4"> 
              <div id="motorcycle"></div> 
            </div> 
            <div class="col-lg-8"> 
              <div id="content"></div> 
            </div> 
          </div> 
        </div> 
          <!-- Scripts at bottom --> 
          <script src='https://cdnjs.cloudflare.com/ajax/libs
            /jquery/2.2.1/jquery.min.js'></script> 
          <script src='https://cdnjs.cloudflare.com/ajax/libs
           /twitter-bootstrap/4.0.0-alpha/js/bootstrap.min.js'></script> 
          <script src="https://cdnjs.cloudflare.com/ajax/libs/
           babel-core/5.8.24/browser.js"></script> 
          <script src="https://cdnjs.cloudflare.com/ajax/libs
            /react/15.0.1/react.js"></script> 
          <script src="https://cdnjs.cloudflare.com/ajax/libs/react
            /15.0.1/react-dom.js"></script> 
          <script type="text/babel" src="img/reviews.js"> </script> 
          <script type="text/babel" src="img/motorcycles.js"> </script> 
      </body> 
      </html> 

```

如您所见，在上一个代码中，我们添加了两个文件，类型为 script text/babel。这些文件将是我们使用 React.js 库构建的应用程序组件。

### 提示

您可以在这里找到有关 React.js 的更多信息：[`facebook.github.io/react/`](https://facebook.github.io/react/)。

1.  在 client 文件夹中，创建一个名为 images 的新文件夹。

您可以将摩托车示例图像复制并粘贴到此文件夹中。此外，您可以在 Packt Publishing 网站和书籍的官方 GitHub 存储库中下载所有示例代码。

# 创建 React 组件

类似于 jQuery 小部件和 AgularJS 指令，有 React.js，这是一个非常有用的库，用于创建界面组件。但是，它不像 AngularJS 或 Ember.js 那样是一个完整的框架。

思考 React.js 的方式是通过思考界面组件：一切都是一个组件，一个组件可能由一个或多个组件组成。

请参阅以下图：

![创建 React 组件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_012.jpg)

模拟 React.js 组件的屏幕截图

让我们逐个创建组件，以便更好地理解：

1.  在 client 文件夹中，创建一个名为 js 的新文件夹。

1.  在 js 文件夹中，创建一个名为 review.js 的新文件，并添加以下内容：

```js
      var Review = React.createClass({ 

               render: function() { 
                     return ( 
                         <div className="list-group-item"> 
                           <small className="text-muted pull-right">
                              {this.props.email}
                           </small> 
                           <h4 className="list-group-item-heading"> 
                                 {this.props.name} 
                           </h4> 
                           <p className="list-group-item-text">
                             {this.props.review}
                           </p> 
                         </div> 
                     ); 
                 } 
               });

```

这是列表项组件。

1.  现在让我们添加 ReviewBox。在上一个代码之后添加以下代码：

```js
     var ReviewBox = React.createClass({ 
           loadReviewsFromServer: function() { 
                 $.ajax({ 
                       url: this.props.api, 
                       type: 'GET', 
                       dataType: 'json', 
                       cache: false, 
                       success: function(data) { 
                             console.log(data); 
                             this.setState({data: data}); 
                       }.bind(this), 
                       error: function(xhr, status, err) { 
                             console.error(this.props.api, status,
                               err.toString()); 
                       }.bind(this) 
                 }); 
           }, 
           handleReviewSubmit: function(review) { 
                 var reviews = this.state.data; 
                 // Don' use Date.now() on production, this is here
                    just for the example. 
                 review.id = Date.now().toString(); 
                 var newReviews = reviews.concat([review]); 
                  this.setState({data: newReviews}); 
                 console.log(review); 
                 $.ajax({ 
                       url: this.props.api, 
                       dataType: 'json', 
                       type: 'POST', 
                      data: review, 
                       success: function(data) { 
                             console.log(data); 
                       }.bind(this), 
                       error: function(xhr, status, err) { 
                             this.setState({data: reviews}); 
                             console.error(this.props.api, status,
                               err.toString()); 
                       }.bind(this) 
                 }); 
           }, 
           getInitialState: function() { 
                 return { 
                       data: [] 
                 }; 
           }, 
           componentDidMount: function() { 
                 this.loadReviewsFromServer(); 
           }, 
           render: function() { 
                 return ( 
                       <div> 
                             <ReviewList data={this.state.data} /> 
                             <ReviewForm onReviewSubmit=
                              {this.handleReviewSubmit} /> 
                       </div> 
                  ); 
          } 
     });

```

这是 ReviewBox 组件及其两个接收组件；一个是 ReviewList 组件，另一个是 ReviewForm 组件。请注意，我们使用 jQuery 的$.get()函数从 localhost:3000/api/reviews 获取评论，使用 GET 方法。

此外，我们有一个名为 handleReviewSubmit()的函数，用于处理表单提交操作到相同的端点：localhost:3000/api/reviews，使用 POST 方法。

我们有 getInitialState()函数来设置一个数据数组，它在 componentDidMount()函数上等待一个 promise 函数：

1.  现在让我们将 ReviewList 组件添加到 reviews.js 中。在上一个代码之后添加以下代码：

```js
      var ReviewList = React.createClass({ 
             render: function() { 
               var reviewNodes = this.props.data.map(function(review)
               { 
                 return ( 
                     <Review name={review.name} review={review.review}
                       email={review.email} key={review.id}> </Review> 
                 ); 
               }); 
               return ( 
                   <div className="list-group"> 
                           {reviewNodes} 
                   </div> 
               ); 
             } 
      });

```

1.  现在我们添加 ReviewForm 组件。在上一个代码之后添加以下代码：

```js
      var ReviewForm = React.createClass({ 
          getInitialState: function() { 
               return {name: '', email: '', review: '', model: ''}; 
          }, 
          handleAuthorChange: function(e) { 
              this.setState({name: e.target.value}); 
          }, 
          handleEmailChange: function(e) { 
               this.setState({email: e.target.value}); 
          }, 
          handleTextChange: function(e) { 
               this.setState({review: e.target.value}); 
          }, 
          handleSubmit: function(e) { 
               e.preventDefault(); 
               var name = this.state.name.trim(); 
               var email = this.state.email.trim(); 
               var review = this.state.review.trim(); 
               var model = '57337088fabe969f2dd4078e';
                if (!review || !name) { 
                    return; 
                }
                this.props.onReviewSubmit({name: name, email:email,
                  model:model, review: review}); 
                this.setState({name: '', email: '', review: '',
                  model: ''}); 
           }, 
           render: function() { 
               return ( 
                 <div> 
                   <hr/> 
                     <form onSubmit={this.handleSubmit}> 
                       <div className="row"> 
                         <div className="col-lg-6"> 
                           <fieldset className="form-group"> 
                             <label for="InputName">Name</label> 
                             <input type="review" className=
                               "form-control" id="InputName"
                                placeholder="Name" value=
                                {this.state.name} 
                              onChange={this.handleAuthorChange} /> 
                            </fieldset> 
                          </div> 
                          <div className="col-lg-6"> 
                            <fieldset className="form-group"> 
                              <label for="InputEmail">Email</label> 
                              <input type="review" className="form-control"
                                id="InputEmail" placeholder="Email" value=
                                {this.state.email} 
                              onChange={this.handleEmailChange}/> 
                            </fieldset> 
                          </div> 
                        </div> 
                        <fieldset className="form-group"> 
                        <label for="TextareaFeedback">Feedback</label> 
                        <textarea className="form-control"
                         id="TextareaFeedback" rows="3" value=
                         {this.state.review} onChange=
                         {this.handleTextChange} /> 
                        </fieldset> 

                        <button type="submit" className=
                          "btn btn-primary" value="Post">
                             Submit
                        </button> 
                     </form> 
                 </div> 
                 ); 
            } 
      });

```

1.  最后，我们只需要创建一个 React 方法来呈现所有内容。在上一个代码之后添加以下代码：

```js
      ReactDOM.render( 
         <ReviewBox api="/api/reviews"/>,
           document.getElementById('content') 
      ); 

```

此前的代码片段将在<div id="content"></div>中呈现 ReviewBox 组件；简要类比 CSS 类，我们有以下组件结构：

+   ReviewBox

+   ReviewList

+   回顾

+   ReviewForm

因此，ReviewBox 组件的 render()方法呈现两个组件：

```js
      render: function() { 
         return ( 
            <div> 
              <ReviewList data={this.state.data} /> 
              <ReviewForm onCommentSubmit={this.handleReviewSubmit} /> 
            </div> 
        ); 
      } 

```

现在我们对摩托车组件做同样的操作：

1.  在 common/js 文件夹中创建一个名为 motorcycle.js 的新文件，并添加以下代码：

```js
      // create a interface component for motorcycle item 
      var Motorcycle = React.createClass({ 
        render: function() { 
            return ( 
              <div className="card"> 
                <img className="card-img-top" src={this.props.image}
                  alt={this.props.make} width="100%"/> 
                <div className="card-block"> 
                  <h4 className="card-title">{this.props.make}</h4> 
                  <p className="card-text">{this.props.description}</p> 
                </div> 
                <ul className="list-group list-group-flush"> 
                  <li className="list-group-item"><strong>Model:
                    </strong> {this.props.model}</li> 
                  <li className="list-group-item"><strong>Category:
                    </strong> {this.props.category}</li> 
                  <li className="list-group-item"><strong>Year:
                    </strong> {this.props.year}</li> 
                </ul> 
              </div> 
            ); 
        } 
      });

```

1.  让我们添加 MotorcycleBox 组件。在上一行之后添加以下代码：

```js
      // create a motorcycle box component 
      var MotorcycleBox = React.createClass({ 
         loadMotorcyclesFromServer: function() { 
             $.ajax({ 
               url: this.props.api, 
               type: 'GET', 
               dataType: 'json', 
               cache: false, 
               success: function(data) { 
                 console.log(data); 
                 this.setState({data: data}); 
               }
               .bind(this), 
               error: function(xhr, status, err) { 
                 console.error(this.props.api, status,
                 err.toString()); 
               }
               .bind(this) 
             }); 
         }, 
         getInitialState: function() { 
             return { 
               data: [] 
             }; 
         }, 
         componentDidMount: function() { 
             this.loadMotorcyclesFromServer(); 
         }, 
         render: function() { 
           return ( 
             <div> 
              <MotorcycleList data={this.state.data} /> 
            </div> 
          ); 
        }
      });

```

1.  让我们创建一个 motorcycleList 组件。在上一行之后添加以下代码：

```js
      // create a motorcycle list component 
      var MotorcycleList = React.createClass({ 
        render: function() { 
          var motorcycleNodes = this.props.data.map(function(motorcycle)
          { 
            console.log(motorcycle); 
            return ( 
              <Motorcycle image={motorcycle.image} make=
                {motorcycle.make} model={motorcycle.model} description=
                {motorcycle.description} category={motorcycle.category}
                year={motorcycle.year} key={motorcycle.id}>
              </Motorcycle> 
            ); 
          }); 
          return ( 
            <div className="motorcycles"> 
              {motorcycleNodes} 
            </div> 
          ); 
        }
      }); 

```

请注意，我们创建了一个列表来渲染数据库中的所有摩托车型号。如果您想要在此集合中添加或渲染更多项目，这是推荐的做法。对于我们的示例，我们只有一个。

最后的方法是 render()函数来渲染 MotorcycleBox 组件

1.  在上一行之后添加以下行：

```js
      ReactDOM.render( 
         <MotorcycleBox api="/api/motorcycles"/>, 
           document.getElementById('motorcycle') 
      ); 

```

此渲染方法告诉在 HTML 摩托车 div 标签内渲染 MotorcycleBox 组件：<div id="motorcycle"></div>。

# 创建新的反馈

现在是时候使用我们构建的应用程序创建新的反馈了：

1.  打开终端/Shell 并输入以下命令：

```js
npm start

```

1.  转到 http://localhost:3000/，填写以下数据并点击**提交**按钮：

+   姓名：**约翰·多**

+   电子邮件：**john@doe.com**

+   反馈：**很棒的红白经典摩托车！**

结果会立即显示在屏幕上，如下截图所示。

![创建新的反馈](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_013.jpg)

新创建的反馈的屏幕截图

## 简单检查端点

让我们对我们的 API 进行简单的检查。前面的图像显示了特定型号摩托车的四条反馈；我们可以看到在图像中出现了评论的计数，但我们的 API 有一个端点显示这些数据。

转到 http://localhost:3000/api/reviews/count，我们可以看到以下结果：

```js
      { 
         count: 4 
      } 

```

## 禁用远程 LoopBack 端点

默认情况下，LoopBack 创建了许多额外的端点，而不仅仅是传统的 CRUD 操作。我们之前看到了这一点，包括前面的例子。但有时，我们不需要通过 API 资源公开所有端点。

让我们看看如何使用几行代码来减少端点的数量：

1.  打开 common/models/review.js 并添加以下突出显示的代码行：

```js
      module.exports = function(Review) { 
         // Disable endpoint / methods 
         Review.disableRemoteMethod("count", true); 
         Review.disableRemoteMethod("exists", true); 
         Review.disableRemoteMethod("findOne", true); 
         Review.disableRemoteMethod('createChangeStream', true); 
         Review.disableRemoteMethod("updateAll", true); 
      }; 

```

1.  重新启动应用程序，打开您的终端/Shell，并输入以下命令：

```js
npm start

```

1.  转到 http://localhost:3000/explorer/，点击**review**模型。

结果将如下图所示，只有 CRUD 端点：

![禁用远程 LoopBack 端点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-6x-bp/img/image_06_014.jpg)

评论端点的屏幕截图

### 提示

您可以在以下链接找到有关隐藏和显示端点的更多信息：[`docs.strongloop.com/display/public/LB/Exposing+models+over+REST#ExposingmodelsoverREST-Hidingendpointsforrelatedmodels`](https://docs.strongloop.com/display/public/LB/Exposing+models+over+REST#ExposingmodelsoverREST-Hidingendpointsforrelatedmodels)。

# 摘要

在本章中，我们讨论了使用 LoopBack 框架创建健壮 API 的过程，并涉及了关于 Web 应用作为数据库、模型之间关系和数据源的一些非常重要的点。

我们还看到了 Express 和 Loopback 之间的一些相似之处，并学会了如何使用 API 资源的 Web 界面。

我们使用 React.js 库构建了一个交互式界面，并接近了 React.js 的主要概念，即组件的创建。

在下一章中，我们将看到如何使用 Node.js 的一些非常有用的资源构建实时应用程序。
