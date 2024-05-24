# 通过构建安卓应用学习 Kotlin（二）

> 原文：[`zh.annas-archive.org/md5/201D65C8BC4C6A97336C0B7173DD6D6D`](https://zh.annas-archive.org/md5/201D65C8BC4C6A97336C0B7173DD6D6D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Google 的位置服务

在上一章中，我们构建了我们的**基于位置的警报**（LBA）应用程序，包括 Google 地图，添加了标记和自定义位置，并为接收用户输入设置了 UI。

我们现在将专注于将 Google 位置 API 与我们的应用程序集成，并在用户的位置上接收更新。用户输入的感兴趣的位置将被保存并与接收到的警报位置更新进行比较，以便在用户到达感兴趣的区域时触发警报。

Google 提供了各种方式来访问和识别用户的位置。Google 位置 API 提供了关于用户上次已知位置的信息，显示位置地址，接收位置更改的持续更新等。开发人员可以添加地理围栏 - 围绕地理区域的围栏 - 任何时候用户通过地理围栏时都可以生成警报。

在本章中，我们将学习如何：

+   使用 Google 位置 API

+   接收用户当前位置的更新

+   利用用户共享首选项来保存用户感兴趣的位置

+   匹配并在用户到达感兴趣的位置时显示警报

本章的主要重点是介绍和解释我们应用程序中位置的概念和用法。考虑到这一目标，这些概念是通过应用程序在前台运行时接收位置更新来解释的。所需权限的处理也以更简单的方式处理。

# 集成共享首选项

我们的应用程序用户将输入他们希望触发警报的所需位置。用户输入位置的“纬度”和“经度”，以便我们将其与用户所在的当前位置进行比较，我们需要将他们输入的详细信息存储为所需位置。

共享首选项是基于文件的存储，包含键值对，并提供了更容易的读写方式。共享首选项文件由 Android 框架管理，文件可以是私有的或共享的。

让我们首先将共享首选项集成到我们的代码中，并保存用户在 UI 屏幕上输入的纬度和经度用于警报。

共享首选项为我们提供了以键值对的形式保存数据的选项。虽然我们可以使用通用的共享首选项文件，但最好为我们的应用程序创建一个特定的共享首选项文件。

我们需要为我们的应用程序定义一个共享首选项文件的字符串。导航到 app | src | main | res | values | strings.xml。让我们添加一个新的字符串`PREFS_NAME`，并将其命名为`LocationAlarmFile`：

```kt
<resources>
     <string name="app_name">LocationAlarm</string>
     <string name="title_activity_maps">Map</string>
     <string name="Settings">Settings</string>
    <string name="PREFS_NAME">LocationAlarmFile</string> </resources>
```

我们将在我们的`SettingsActivity`类中添加以下代码，以捕获用户输入并将其保存在共享首选项文件中。共享首选项文件通过在资源文件中引用字符串`PREFS_NAME`来打开，并且文件以`MODE_PRIVATE`打开，这表示该文件仅供我们的应用程序使用。

一旦文件可用，我们打开编辑器并使用`putString`将用户输入的纬度和经度作为字符串共享。

```kt
val sharedPref = this?.getSharedPreferences(getString(R.string.PREFS_NAME),Context.MODE_PRIVATE) ?: return with(sharedPref.edit()){ putString("userLat", Lat?.text.toString())
     putString("userLang",Lang?.text.toString())
     commit()
```

从共享首选项中读取和显示：

```kt
      val sharedPref = 
 this?.getSharedPreferences(getString(R.string.PREFS_NAME), 
      Context.MODE_PRIVATE) ?: return AlarmLat = 
     java.lang.Double.parseDouble(sharedPref.getString("userLat",   
 "13.07975"))
         AlarmLong = 
     java.lang.Double.parseDouble(sharedPref.getString("userLang", 
 "80.1798347"))
```

用户将收到有关设置警报的警报：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e94c0720-b24e-426b-8d67-08a28aedecdc.png)

用户输入的纬度将存储并从共享首选项中读取并显示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/3eb7b5d4-409e-47f2-bd74-31eb98885280.png)

用户输入的经度也将从共享首选项中读取并显示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4e0402fa-652e-4d8c-bf4d-295149b723e5.png)

# 添加权限

Google Play 服务提供了可以集成和使用的基于位置的服务。添加位置服务并使用它们需要权限来识别并从用户那里获取位置更新。

要使用来自 Play 服务的 Google 位置服务，我们需要在`build.gradle`文件中包含`play-services-location`：

```kt
dependencies {
    compile 'com.google.android.gms:play-services-location:11.8.0'
}
```

重要的是**仅**从 Google Play 服务中包含应用程序所需的特定功能。例如，在这里我们需要位置服务，因此我们需要指定位置的服务。包含所有 Google Play 服务将使应用程序大小变得庞大；请求不真正需要的权限。

我们还需要在 `AndroidManifest.xml` 文件中添加访问精确定位的权限。这使我们可以从网络提供商和 GPS 提供商获取位置详细信息：

```kt
 <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

在运行时，我们需要检查设备是否已启用位置；如果没有，我们将显示一条消息，请求用户启用位置并授予权限。

`checkLocation` 布尔函数用于判断设备是否已启用位置：

```kt
private fun checkLocation(): Boolean {
         if(!isLocationEnabled())
             Toast.makeText(this,"Please enable Location and grant permission for this app for Location",Toast.LENGTH_LONG).show()
         return isLocationEnabled();
     }

private fun isLocationEnabled(): Boolean {
     locationManager = getSystemService(Context.LOCATION_SERVICE) as 
     LocationManager
     return locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER) || locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
 }
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/f698a5c3-d5f2-40d4-b344-897e05332272.png)

# 位置 API 的集成

我们将集成位置 API 到我们的应用程序中以接收位置更新。位置 API 的集成涉及代码的一些更改。让我们详细讨论这些更改。

# 类和变量

Google 位置 API 的集成需要 `MapsActivity` 实现 `GoogleAPIClient`、`ConnectionCallbacks` 和连接失败监听器。让我们继续对 `MapsActivity` 进行更改。之前，`MapsActivity` 扩展了 `AppCompatActivity` 并实现了 `OnMapReadyCallback` 接口。现在，由于我们需要使用位置 API，我们还必须实现 `GoogleAPIClient`、`ConnectionCallbacks` 和 `onConnectionFailedListener`，如下所示：

```kt
class MapsActivity : AppCompatActivity(), OnMapReadyCallback ,GoogleApiClient.ConnectionCallbacks, GoogleApiClient.OnConnectionFailedListener, com.google.android.gms.location.LocationListener {
```

我们声明了 `GoogleMap` 所需的变量和其他变量，用于存储来自用户和位置 API 的纬度和经度：

```kt
    private lateinit var mMap: GoogleMap
    private var newLat: Double? = null
    private var newLang: Double? = null
    private var chennai: LatLng? = null

    private var AlarmLat: Double? = null
    private var AlarmLong: Double? = null
    private var UserLat: Double? = null
    private var UserLong: Double? = null

     //location variablesprivate val TAG = "MapsActivity" private lateinit var mGoogleApiClient: GoogleApiClient
    private var mLocationManager: LocationManager? = null
    lateinit var mLocation: Location
    private var mLocationRequest: LocationRequest? = null
```

我们声明 `UPDATE_INTERVAL`，即我们希望从位置 API 接收更新的间隔，以及 `FASTEST_INTERVAL`，即我们的应用程序可以处理更新的速率。我们还声明 `LocationManager` 变量：

```kt
 private val UPDATE_INTERVAL = 10000.toLong() // 10 seconds rate at 
     //  which we would like to receive the updates
     private val FASTEST_INTERVAL: Long = 5000 // 5 seconds - rate at  
     //  which app can handle the update lateinit var locationManager: LocationManager
```

在 `onCreate` 函数中，我们为 UI 设置内容视图，并确保 `GoogleApiClient` 已实例化。我们还请求用户启用位置如下：

`onCreate()`：

```kt
   override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         setContentView(R.layout.*activity_maps*)
         // Obtain the SupportMapFragment and get notified when the map    
         is ready to be used. val mapFragment = *supportFragmentManager
                * .findFragmentById(R.id.*map*) as SupportMapFragment
         mapFragment.getMapAsync(this)

         mGoogleApiClient = GoogleApiClient.Builder(this)
                 .addConnectionCallbacks(this)
                 .addOnConnectionFailedListener(this)
                 .addApi(LocationServices.API)
                 .build()

         mLocationManager =   
 this.getSystemService(Context.LOCATION_SERVICE) as  
         LocationManager
         checkLocation()
 }
```

# Google API 客户端

声明、初始化和管理 Google API 客户端的连接选项需要在 Android 应用程序的生命周期事件中处理。一旦建立连接，我们还需要获取位置更新。

在 `onStart` 方法中，我们检查 `mGoogleAPIClient` 实例是否不为空，并请求初始化连接：

```kt
   override fun onStart() {
         super.onStart();
         if (mGoogleApiClient != null) {
             mGoogleApiClient.connect();
         }
     }
```

在 `onStop` 方法中，我们检查 `mGoogleAPIClient` 实例是否已连接，如果是，则调用 `disconnect` 方法：

```kt
    override fun onStop() {
         super.onStop();
         if (mGoogleApiClient.isConnected()) {
             mGoogleApiClient.disconnect();
         }
     }
```

如果出现问题并且连接被挂起，我们在 `onConnectionSuspended` 方法中请求重新连接：

```kt
     override fun onConnectionSuspended(p0: Int) {

         Log.i(TAG, "Connection Suspended");
         mGoogleApiClient.connect();
     }
```

如果 Google 位置 API 无法建立连接，我们通过获取错误代码来记录连接失败的原因：

```kt
     override fun onConnectionFailed(connectionResult: 
        ConnectionResult) {
     Log.i(TAG, "Connection failed. Error: " + 
        connectionResult.getErrorCode());
     }
```

在 `onConnected` 方法中，我们首先检查是否有 `ACCESS_FINE_LOCATION` 权限，并且 `ACCESS_COARSE_LOCATION` 确实存在于清单文件中。

一旦确保已授予权限，我们调用 `startLocationUpdates()` 方法：

```kt
override fun onConnected(p0: Bundle?) {

         if (ActivityCompat.checkSelfPermission(this,   
            Manifest.permission.ACCESS_FINE_LOCATION) != 
            PackageManager.PERMISSION_GRANTED && 
            ActivityCompat.checkSelfPermission(this, 
            Manifest.permission.ACCESS_COARSE_LOCATION) != 
            PackageManager.PERMISSION_GRANTED) {

             return;
         }
         startLocationUpdates();
```

`fusedLocationProviderClient` 提供当前位置详细信息，并将其分配给 `mLocation` 变量：

```kt
var fusedLocationProviderClient :
         FusedLocationProviderClient =   
         LocationServices.getFusedLocationProviderClient(this);
         fusedLocationProviderClient .getLastLocation()
         .addOnSuccessListener(this, OnSuccessListener<Location> {   
         location ->
                     if (location != null) {
                         mLocation = location;
 } }) }
```

`startLocationUpdates` 创建 `LocationRequest` 实例，并提供我们设置的更新参数。我们还调用 `FusedLocationAPI` 并请求位置更新：

```kt

 protected fun startLocationUpdates() {
          // Create the location request mLocationRequest = LocationRequest.create()
                 .setPriority(LocationRequest.PRIORITY_HIGH_ACCURACY)
                 .setInterval(UPDATE_INTERVAL)
                 .setFastestInterval(FASTEST_INTERVAL);
         // Request location updates if (ActivityCompat.checkSelfPermission(this, 
          Manifest.permission.ACCESS_FINE_LOCATION) !=   
          PackageManager.PERMISSION_GRANTED && 
          ActivityCompat.checkSelfPermission(this, 
          Manifest.permission.ACCESS_COARSE_LOCATION) != 
          PackageManager.PERMISSION_GRANTED) {
             return;
         }

      LocationServices.FusedLocationApi.requestLocationUpdates(
 mGoogleApiClient, mLocationRequest, this);
     }

```

`onLocationChanged` 方法是一个重要的方法，我们可以在其中获取用户当前位置的详细信息。我们还从共享偏好中读取用户输入的警报的纬度和经度。一旦我们获得了这两组详细信息，我们调用 `CheckAlarmLocation` 方法，该方法匹配纬度/经度并在用户到达感兴趣的区域时提醒用户：

```kt
override fun onLocationChanged(location: Location) { 
        val sharedPref =  
 this?.getSharedPreferences(getString(R.string.*PREFS_NAME*), 
      Context.*MODE_PRIVATE*)
           ?: return
        AlarmLat = 
      java.lang.Double.parseDouble(sharedPref.getString("userLat", 
 "13.07975"))
        AlarmLong = 
      java.lang.Double.parseDouble(sharedPref.getString("userLang", 
 "80.1798347"))

         UserLat = location.latitude
 UserLong = location.longitude
 val AlarmLat1 = AlarmLat val AlarmLong1 = AlarmLong
         val UserLat1 = UserLat
         val UserLong1 = UserLong

         if(AlarmLat1 != null && AlarmLong1 != null && UserLat1 != null 
         && UserLong1 != null){

      checkAlarmLocation(AlarmLat1,AlarmLong1,UserLat1,UserLong1)
         }
     }
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d2b3a7d9-134b-41af-83ef-b778674eb1a4.png)

# 匹配位置

`startLocationUpdates`方法根据我们设置的间隔持续提供用户的当前纬度和经度。我们需要使用获取到的纬度和经度信息，并将其与用户输入的用于设置警报的纬度和经度进行比较。

用户输入感兴趣的位置时，我们会显示警报消息，告知用户已经到达设置了警报的区域：

```kt
fun checkAlarmLocation(AlarmLat : Double, AlarmLong : Double, UserLat : Double,UserLong : Double) {

    Toast.makeText(this,"Check Alarm Called" + AlarmLat + "," + AlarmLong + "," + UserLat + "," + UserLong,Toast.*LENGTH_LONG* ).show()

         var LatAlarm: Double
         var LongAlarm: Double
         var LatUser: Double
         var LongUser: Double

         LatAlarm = Math.round(AlarmLat * 100.0) / 100.0;
         LongAlarm = Math.round(AlarmLong * 100.0) / 100.0;

         LatUser = Math.round(UserLat * 100.0) / 100.0;
         LongUser = Math.round(UserLong * 100.0) / 100.0;

Toast.makeText(this,"Check Alarm Called" + LatAlarm + "," + LongAlarm + "," + LatUser + "," + LongUser,Toast.*LENGTH_LONG* ).show()

         if (LatAlarm == LatUser && LongAlarm == LongUser) {
             Toast.makeText(this, "User has reached the area for which 
             alarm has been set", Toast.LENGTH_LONG).show();
         }
     }
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/adf9fa70-f09d-4fdd-bc66-7d8439a26a79.png)

# 摘要

在本章中，我们继续开发基于位置的闹钟应用程序，利用了来自 Google Play 服务的 Google 位置 API，并利用了提供警报的功能，当用户进入感兴趣的区域时。

我们学习了如何使用共享偏好来持久化用户输入的数据，检索相同的数据，并使用位置 API 来将用户的当前位置与感兴趣的区域进行匹配。


# 第九章：连接外部世界-网络

我们生活在数字通信的时代。手持设备在通信中起着重要作用，并影响人们的互动方式。在上一章中，我们讨论了 Android 的一个强大功能——识别用户的位置并根据位置定制服务。在本章中，我们将专注于 Android 设备最有用和强大的功能之一——网络和连接到外部世界。

虽然我们将简要介绍网络连接的重要概念和 Android 框架对网络的支持，但我们将重点关注内置的第三方库的配置和使用。我们还将学习如何从 URL 加载图像并在我们创建的示例应用程序中显示它。

我们将涵盖以下内容：

+   网络连接

+   Android 框架对网络的支持

+   使用内置库

+   使用第三方库

# 网络连接

了解和识别用户连接的网络的状态和类型对于为用户提供丰富的体验非常重要。Android 框架为我们提供了一些类，我们可以使用它们来查找网络的详细信息：

+   `ConnectivityManager`

+   `NetworkInfo`

虽然`ConnectivityManager`提供有关网络连接状态及其变化的信息，但`NetworkInfo`提供有关网络类型（移动或 Wi-Fi）的信息。

以下代码片段有助于确定网络是否可用，以及设备是否连接到网络：

```kt
fun isOnline(): Boolean {
    val connMgr = getSystemService(Context.CONNECTIVITY_SERVICE) as  
    ConnectivityManager
    val networkInfo = connMgr.activeNetworkInfo
    return networkInfo != null && networkInfo.isConnected
}
```

`isOnline()`方法根据`ConnectivityManager`返回的结果返回一个`Boolean`——true 或 false。`connMgr`实例与`NetworkInfo`一起使用，以查找有关网络的信息。

# 清单权限

访问网络并发送/接收数据需要访问互联网和网络状态的权限。应用程序的清单文件必须定义以下权限，以便应用程序利用设备的网络：

```kt
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
```

互联网权限允许应用程序通过启用网络套接字进行通信，而访问网络状态权限使其能够查找有关可用网络的信息。

Android 框架为应用程序提供了一个默认意图`MANAGE_NETWORK_USAGE`，用于管理网络数据。处理该意图的活动可以针对特定的应用程序进行实现：

```kt
  <intent-filter>
   <action android:name="android.intent.action.MANAGE_NETWORK_USAGE" />
   <category android:name="android.intent.category.DEFAULT" />
  </intent-filter>
```

# Volley 库

通过 HTTP 协议与 Web 服务器通信并以字符串、JSON 和图像的形式交换信息的能力使应用程序更加交互，并为用户提供丰富的体验。Android 具有一个名为`Volley`的内置 HTTP 库，可以直接进行信息交换。

除了使信息交换更加容易外，`Volley`还提供了更容易处理请求的整个生命周期的手段，如调度、取消、设置优先级等。

`Volley`非常适用于轻量级网络操作，并使信息交换更加容易。对于大型下载和流操作，开发人员应使用下载管理器。

# 同步适配器

使应用程序中的数据与 Web 服务器同步，使开发人员能够为用户提供丰富的体验。Android 框架提供了**同步适配器**，可以在定义的周期间隔内进行数据同步。

类似于`Volley`，同步适配器具有处理数据传输的生命周期和提供无缝数据交换的所有设施。

同步适配器实现通常包含一个存根验证器、一个存根内容提供程序和一个同步适配器。

# 第三方库

除了 Android 框架的内置支持外，我们还有相当多的第三方库可用于处理网络操作。其中，来自 Square 的`Picasso`和来自 bumptech 的`Glide`是广泛使用的图像下载和缓存库。

在这一部分，我们将专注于实现这两个库——`Picasso`和`Glide`——从特定 URL 加载图像并在我们的示例应用程序中显示它。

网络调用**绝对不应该**在主线程上进行。这样做会导致应用程序变得不够响应，并创建应用程序无响应的情况。相反，我们应该创建单独的工作线程来处理这样的网络调用，并在请求被处理时提供信息。

# Picasso

在这个示例项目中，让我们了解如何使用 Square 的`Picasso`库从指定的 URL 加载图像。

让我们创建一个新的 Android 项目，并将其命名为 ImageLoader。我们需要确保已经勾选了 Kotlin 支持。

对于 Image Loader 示例，我们可以选择空活动继续：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a72a3ccd-c160-45d2-a4af-bea01c47a226.png)

让我们将活动命名为`MainActivity`，默认情况下会出现这个活动，并将 XML 命名为`activity_main`：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d26151dc-849d-4469-b1a2-b046f862eaf8.png)

# 用户界面 - XML

生成的默认 XML 代码将包含一个`TextView`。我们需要稍微调整 XML 代码，用`ImageView`替换`TextView`。这个`ImageView`将提供一个占位符，用于显示从 URL 获取的图片，使用`Picasso`。

接下来的 XML 代码显示了默认 XML 包含`TextView`；我们将用`ImageView`替换`TextView`：

```kt
*<?*xml version="1.0" encoding="utf-8"*?>
* <android.support.constraint.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     xmlns:tools="http://schemas.android.com/tools"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     tools:context="com.natarajan.imageloader.MainActivity">

     <TextView
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:text="Hello World!"
         app:layout_constraintBottom_toBottomOf="parent"
 app:layout_constraintLeft_toLeftOf="parent"
         app:layout_constraintRight_toRightOf="parent"
         app:layout_constraintTop_toTopOf="parent" />

 </android.support.constraint.ConstraintLayout>
```

修改后的 XML 中包含一个`ImageView`，如下面的代码块所示。我们可以通过从小部件中拖动`ImageView`或在 XML 布局中输入代码来轻松添加它。在`ImageView`中，我们已经标记它以显示启动器图标作为占位符：

```kt
*<?*xml version="1.0" encoding="utf-8"*?>
* <android.support.constraint.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:app="http://schemas.android.com/apk/res-auto"
     xmlns:tools="http://schemas.android.com/tools"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     tools:context="com.natarajan.imageloader.MainActivity">

     <ImageView
         android:id="@+id/imageView"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         app:srcCompat="@mipmap/ic_launcher"
         app:layout_constraintBottom_toBottomOf="parent"
         app:layout_constraintLeft_toLeftOf="parent"
         app:layout_constraintRight_toRightOf="parent"
         app:layout_constraintTop_toTopOf="parent"
         tools:layout_editor_absoluteX="139dp"
         tools:layout_editor_absoluteY="219dp" /> 
 </android.support.constraint.ConstraintLayout>
```

`ImageViewer`在占位符上显示启动器图标，用于从 URL 加载图像时显示。只要我们在 XML 中进行更改，启动器图标就会显示出来：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d8f504cc-dd4f-4670-9f0d-f744a011a103.png)

# build.gradle

我们需要在`build.gradle`的依赖项中添加`implementation com.square.picasso.picasso:2.71828`。在撰写本文时，版本 2.71828 是最新版本。为了确保使用最新版本，最好检查[`square.github.io/picasso/`](http://square.github.io/picasso/)，并在 Gradle 依赖项中使用最新版本。

我们需要在`build.gradle`文件的依赖项部分中添加以下行，以便我们的应用程序可以使用`Picasso`：

implementation `com.squareup.picasso:picasso:2.71828`

修改后的`build.gradle`文件应该如下所示：

```kt
dependencies {
    implementation fileTree(dir: 'libs', include: ['*.jar'])
    implementation"org.jetbrains.kotlin:kotlin-stdlib-jre7:$kotlin_version"
    implementation 'com.android.support:appcompat-v7:26.1.0'
    implementation 'com.android.support.constraint:constraint-layout:1.1.0'
    implementation 'com.squareup.picasso:picasso:2.71828'
    testImplementation 'junit:junit:4.12'
    androidTestImplementation 'com.android.support.test:runner:1.0.1'
    androidTestImplementation 'com.android.support.test.espresso:espresso-core:3.0.1' }
```

# Kotlin 代码

生成的默认 Kotlin 代码将有一个名为`MainActivity`的类文件。这个类文件扩展了`AppCompatActivity`，提供了支持库操作栏功能。

代码在`onCreate`方法中加载了`activity_main`中定义的 XML，并在加载时显示它。`setContentView`读取了在`activity_main`中定义的 XML 内容，并在加载时显示`ImageView`：

```kt
package com.natarajan.imageloader

 import android.support.v7.app.AppCompatActivity
 import android.os.Bundle
 import kotlinx.android.synthetic.main.activity_main.*

 class MainActivity : AppCompatActivity() {

     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         setContentView(R.layout.activity_main)
     }
 }
```

我们已经通过用`ImageView`替换默认的`TextView`对 XML 进行了更改。我们需要在我们的 Kotlin 代码中反映这些更改，并使用`Picasso`来加载图像。

我们需要为我们的程序添加`ImageView`和`Picasso`的导入，以便使用这些组件：

```kt
import android.widget.ImageView
import com.squareup.picasso.Picasso
```

由于我们已经导入了`Picasso`并确保了依赖项已添加，我们应该能够通过一行代码加载数据，`Picasso.get().load("URL").into(ImageView)`：

```kt
Picasso.get().load("http://i.imgur.com/DvpvklR.png").into(imageView);
```

用于 Picasso 图片加载的最终修改后的 Kotlin 类应该如下所示：

```kt
package com.natarajan.imageloader 
import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.widget.ImageView
import com.squareup.picasso.Picasso
import kotlinx.android.synthetic.main.activity_main.*

 class MainActivity : AppCompatActivity() {

 override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         setContentView(R.layout.*activity_main*)
        Picasso.get().load("http://i.imgur.com/DvpvklR.png").into(imageView);
    }
 }
```

# 清单权限

我们需要确保我们的应用程序已经添加了访问互联网的权限。这是必需的，因为我们将从指定的 URL 下载图像，并在我们的`ImageViewer`中显示它。

我们已经详细介绍了所需的清单权限。让我们继续添加这个权限：

```kt
    <uses-permission android:name="android.permission.INTERNET"></uses-permission>
```

修改后的 XML 应该如下所示：

```kt
*<?*xml version="1.0" encoding="utf-8"*?>
* <manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.natarajan.imageloader">

     <uses-permission android:name="android.permission.INTERNET">
    </uses-permission>

     <application
         android:allowBackup="true"
         android:icon="@mipmap/ic_launcher"
         android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round"
         android:supportsRtl="true"
         android:theme="@style/AppTheme">
         <activity android:name=".MainActivity">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN" />
                  <category  
 android:name="android.intent.category.LAUNCHER" />
             </intent-filter>
         </activity>
     </application>
  </manifest>
```

现在我们已经完成了对 XML、Kotlin 代码、`build.gradle` 和 `AndroidManifest` 文件的更改，是时候启动我们的应用程序并了解通过 `Picasso` 无缝加载图像的过程了。

一旦我们运行应用程序，我们应该能够看到我们的设备加载页面，显示应用程序名称 ImageLoader，并从以下 URL 显示图像：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6d8a550f-cc50-454e-ac74-ec7f413f040f.png)

# Glide

`Glide` 是 bumptech 的另一个非常流行的图像加载库。我们将看看如何使用 `Glide` 并从特定的 URL 加载图像。

让我们继续对 `build.gradle` 和其他相关文件进行 `Glide` 所需的更改。

# build.gradle

我们需要在应用程序的 `build.gradle` 文件中添加插件 `kotlin-kapt` 并添加依赖项。一旦同步了所做的更改，我们就可以在我们的代码中使用 `Glide` 并加载图像。

`Glide` 库使用注解处理。注解处理有助于生成样板代码，并使代码更易于理解。开发人员可以检查生成的代码并了解库生成的样板代码，以观察运行时实际工作的代码：

```kt
apply plugin: 'kotlin-kapt' implementation 'com.github.bumptech.glide:glide:4.7.1' kapt "com.github.bumptech.glide:compiler:4.7.1" 
```

`Glide` 库讨论了在依赖项中添加注解处理器以及 `Glide`。这适用于 Java。对于 Kotlin，我们需要像代码块中所示的那样添加 `kapt` `Glide` 编译器。

修改后的 `build.gradle` 依赖项应如下所示：

```kt
dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
     implementation"org.jetbrains.kotlin:kotlin-stdlib-
     jre7:$kotlin_version"
     implementation 'com.android.support:appcompat-v7:27.1.1'
     implementation 'com.android.support.constraint:constraint-
     layout:1.1.0'
     implementation 'com.squareup.picasso:picasso:2.71828'
     implementation 'com.github.bumptech.glide:glide:4.7.1'
     kapt "com.github.bumptech.glide:compiler:4.7.1" 
 testImplementation 'junit:junit:4.12'
     androidTestImplementation 'com.android.support.test:runner:1.0.1'
     androidTestImplementation 
 'com.android.support.test.espresso:espresso-core:3.0.1' }
```

在项目级别的 `build.gradle` 文件中，我们需要在 `repositories` 部分添加 `mavenCentral()`，如下所示：

```kt
allprojects {
     repositories {
         google()
         mavenCentral()
         jcenter()
     }
```

我们已经完成了对 `build.gradle` 文件的更改；我们应该对 `proguard-rules.pro` 文件进行以下添加。`proguard-rules.pro` 文件使开发人员能够通过删除应用程序中未使用和不需要的代码的引用来缩小 APK 大小。

为了确保 `Glide` 模块**不**受 proguard 缩小的影响，我们需要明确说明应用程序需要**保留**对 `Glide` 的引用。`*-*keep` 命令确保在构建中保留对 `Glide` 和相应模块的引用：

```kt
-keep public class * implements com.bumptech.glide.module.GlideModule
 -keep public class * extends com.bumptech.glide.module.AppGlideModule
 -keep public enum com.bumptech.glide.load.ImageHeaderParser$** {
   **[] $VALUES;
   public *;
 }
# for DexGuard only -keepresourcexmlelements manifest/application/meta-data@value=GlideModule
```

# Kotlin 代码

我们定义了一个名为 `ImageLoaderGlideModule` 的单独类，它扩展了 `AppGlideModule()`。类上的 `@GlideModule` 注解使应用程序能够访问 `GlideApp` 实例。`GlideApp` 实例可以在我们应用程序的各个活动中使用：

```kt
package com.natarajan.imageloader
*/**
  ** Created by admin on 4/14/2018. **/* import com.bumptech.glide.annotation.GlideModule
 import com.bumptech.glide.module.AppGlideModule

@GlideModule
 class ImageLoaderGlideModule : AppGlideModule()
```

我们需要在 `MainActivity` Kotlin 类中进行以下更改，以便通过 `Glide` 加载图像并在应用启动时显示它。

与 `Picasso` 类似，`Glide` 也有一个简单的语法，用于从指定的 URL 加载图像：

```kt
GlideApp.with(this).load("URL").into(imageView);
```

修改后的 `MainActivity` Kotlin 类应如下所示：

```kt
package com.natarajan.imageloader

 import android.support.v7.app.AppCompatActivity
 import android.os.Bundle
 import kotlinx.android.synthetic.main.activity_main.*

 class MainActivity : AppCompatActivity() {

 override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         setContentView(R.layout.activity_main)

     if(imageView != null){

   GlideApp.with(this).load("http://goo.gl/gEgYUd").into(imageView);
       }
    }
 }

```

我们已经完成了 `Glide` 所需的所有更改——`build.gradle`、`Proguard.rules` 和 Kotlin 类文件。我们应该看到应用程序从指定的 URL 加载图像并在 `ImageView` 中显示它。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/bc948b2a-1cd8-4fe7-8f7d-aa7e6516132b.png)

# 摘要

网络和连接到外部世界是 Android 设备非常强大的功能。我们介绍了网络的基础知识，检查网络状态，可用网络类型，以及 Android 框架提供的内置功能来执行网络操作。

我们还详细讨论了第三方库 `Picasso` 和 `Glide`，以及在我们的应用程序中实现这些库。

在下一章中，我们将致力于开发一个简单的待办事项列表应用程序，并讨论各种概念，如列表视图、对话框等，并学习如何在应用程序中使用它们。


# 第十章：开发一个简单的待办事项列表应用程序

在本章中，我们将构建一个简单的待办事项列表应用程序，允许用户添加、更新和删除任务。

在这个过程中，我们将学到以下内容：

+   如何在 Android Studio 中构建用户界面

+   使用 ListView

+   如何使用对话框

# 创建项目

让我们从在 Android Studio 中创建一个新项目开始，名称为 TodoList。在“为移动添加活动”屏幕上选择“添加无活动”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d7dc52e6-5c32-4406-b43f-95c3eae36b1b.png)

当项目创建完成后，通过选择“文件”|“新建”|“Kotlin 活动”来创建一个 Kotlin 活动，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b7306b18-f3e9-443b-86bc-e41d9015966d.png)

这将启动一个新的 Android Activitywizard**。在“为移动添加活动”屏幕上，选择“基本活动”，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e9ea6e05-6b8a-4ec7-95bd-e4526da557ed.png)

现在，在“自定义活动”屏幕上检查启动器活动，并单击“完成”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/ac8da278-3877-4064-b59b-ec2f5d5681d1.png)

# 构建您的 UI

在 Android 中，用户界面的代码是用 XML 编写的。您可以通过以下任一方式构建您的 UI：

+   使用 Android Studio 布局编辑器

+   手动编写 XML 代码

让我们开始设计我们的 TodoList 应用程序。

# 使用 Android Studio 布局编辑器

Android Studio 提供了一个布局编辑器，让您可以通过将小部件拖放到可视化编辑器中来构建布局。这将自动生成 UI 的 XML 代码。

打开`content_main.xml`文件。

确保屏幕底部选择了“设计”选项卡，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/9a012a33-2153-4d95-8821-82b5caaeedc1.png)

要向布局添加组件，只需从屏幕左侧的 Palette 中拖动项目。要查找组件，可以滚动浏览 Palette 上的项目，或者单击 Palette 搜索图标并搜索所需的项目。

如果 Palette 没有显示在您的屏幕上，请选择“查看”|“工具窗口”|“Palette”以显示它。

继续在您的视图中添加`ListView`。当选择一个视图时，它的属性会显示在屏幕右侧的 XML 属性编辑器中。属性编辑器允许您查看和编辑所选组件的属性。继续进行以下更改：

+   将 ID 设置为 list_view

+   将 layout_width 和 layout_height 属性都更改为 match_parent

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/3f3148dd-16b3-4320-aad1-813bcbb587e2.png)

如果属性编辑器没有显示，请选择“查看”|“工具窗口”|“属性”以显示它。

现在，在编辑器窗口底部选择“文本”以查看生成的 XML 代码。您会注意到 XML 代码现在在`ConstraintLayout`中放置了一个`ListView`：

```kt
<?xml version="1.0" encoding="utf-8"?>
<android.support.constraint.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    app:layout_behavior="@string/appbar_scrolling_view_behavior"
    tools:context="com.packtpub.eunice.todolist.MainActivity"
    tools:showIn="@layout/activity_main">

    <ListView
        android:id="@+id/list_view"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        tools:layout_editor_absoluteX="4dp"
        tools:layout_editor_absoluteY="8dp" />
</android.support.constraint.ConstraintLayout>
```

布局始终有一个根元素。在前面的代码中，`ConstraintLayout`是根元素。

您可以选择使用布局编辑器，也可以自己编写 XML 代码。使用布局编辑器还是编写 XML 代码的选择取决于您。您可以使用您最熟悉的选项。我们将继续随着进展对 UI 进行添加。

现在，构建并运行您的代码。如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/5c177ec2-8f16-410f-8d0b-f04425ef94d6.png)

如您所见，该应用目前并不完整。让我们继续添加更多内容。

由于我们将使用`FloatingActionButton`作为用户用来向待办事项列表添加新项目的按钮，我们需要将其图标更改为一个清晰表明其目的的图标。

打开`activity_main.xml`文件：

`android.support.design.widget.FloatingActionButton`的一个属性是`app:srcCompat`。这用于指定**FloatingActionButton**的图标。将其值从`@android:drawable/ic_dialog_email`更改为`@android:drawable/ic_input_add`。

再次构建和运行。现在底部的**FloatingActionButton**看起来像一个添加图标，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a51c3e2f-a232-4e4a-892e-2df78c06832a.png)

# 为用户界面添加功能

目前，当用户单击“添加”按钮时，屏幕底部会显示一个滚动消息。这是因为`onCreate()`方法中的一段代码定义并设置了`FloatingActionButton`的`OnClickListener`：

```kt
fab.setOnClickListener { view ->
    Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
            .setAction("Action", null).show()
}
```

这对于我们的待办事项列表应用程序来说并不理想。让我们继续在`MainActivity`类中创建一个新方法来处理单击事件：

```kt
fun showNewTaskUI() {
}
```

该方法目前什么也不做。我们将很快添加代码来显示适当的 UI。现在，用对新方法的调用替换`setOnClickListener()`调用中的代码：

```kt
fab.setOnClickListener { showNewTaskUI() }
```

# 添加新任务

要添加新任务，我们将向用户显示一个带有可编辑字段的 AlertDialog。

让我们从为对话框构建 UI 开始。右键单击`res/layout`目录，然后选择**新建** | **布局资源文件**，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/01d394c9-1294-4b0c-bc42-6e7eabd9186c.png)

在新资源文件窗口上，将根元素更改为`LinearLayout`，并将文件名设置为`dialog_new_task`。单击“确定”以创建布局，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d6dd7588-d44b-4535-ad08-bf81dd560b12.png)

打开`dialog_new_task`布局，并向`LinearLayout`添加一个`EditText`视图。布局中的 XML 代码现在应该如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:orientation="vertical" android:layout_width="match_parent"
    android:layout_height="match_parent">

    <EditText
        android:id="@+id/task"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:inputType="text"/>

</LinearLayout>
```

`inputType`属性用于指定字段可以接受什么类型的数据。通过指定此属性，用户将显示适当的键盘。例如，如果`inputType`设置为数字，则显示数字键盘：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a4a6bf8e-58dd-4b4c-9d09-cd8e9b8d97c6.png)

现在，让我们继续添加一些我们将在下一节中需要的字符串资源。打开`res/values/strings.xml`文件，并将以下代码添加到`resources`标记中：

```kt
<string name="add_new_task_dialog_title">Add New Task</string>
<string name="save">Save</string>
```

+   `add_new_task_dialog_title`字符串将用作对话框的标题

+   `save`字符串将用作对话框上按钮的文本

使用`AlertDialog`的最佳方法是将其封装在`DialogFragment`中。`DialogFragment`消除了处理对话框生命周期事件的负担。它还使您能够轻松地在其他活动中重用对话框。

创建一个名为`NewTaskDialogFragment`的新 Kotlin 类，并用以下代码替换类定义：

```kt
class NewTaskDialogFragment: DialogFragment() {  // 1

    // 2
    interface NewTaskDialogListener {
        fun onDialogPositiveClick(dialog: DialogFragment, task: String)
        fun onDialogNegativeClick(dialog: DialogFragment)
    }

    var newTaskDialogListener: NewTaskDialogListener? = null  // 3

    // 4
    companion object {
        fun newInstance(title: Int): NewTaskDialogFragment {

            val newTaskDialogFragment = NewTaskDialogFragment()
            val args = Bundle()
            args.putInt("dialog_title", title)
            newTaskDialogFragment.arguments = args
            return newTaskDialogFragment
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {  // 5
        val title = arguments.getInt("dialog_title")
        val builder = AlertDialog.Builder(activity) 
        builder.setTitle(title) 

        val dialogView =    
     activity.layoutInflater.inflate(R.layout.dialog_new_task, null) 
        val task = dialogView.findViewById<EditText>(R.id.task)

        builder.setView(dialogView)
                .setPositiveButton(R.string.save, { dialog, id ->
                    newTaskDialogListener?.onDialogPositiveClick(this, 
                 task.text.toString);
                })
                .setNegativeButton(android.R.string.cancel, { dialog, 
                 id ->
                    newTaskDialogListener?.onDialogNegativeClick(this)
                })
        return builder.create()
     }

  override fun onAttach(activity: Activity) { // 6
        super.onAttach(activity)
        try {
            newTaskDialogListener = activity as NewTaskDialogListener  
        } catch (e: ClassCastException) {
            throw ClassCastException(activity.toString() + " must  
            implement NewTaskDialogListener")
        }

    }
}
```

让我们更仔细地看看这个类做了什么：

1.  该类扩展了`DialogFragment`类。

1.  它声明了一个名为`NewTaskDialogListener`的接口，该接口声明了两种方法：

+   `onDialogPositiveClick(dialog: DialogFragment, task: String)`

+   `onDialogNegativeClick(dialog: DialogFragment)`

1.  它声明了一个类型为`NewTaskDialogListener`的变量。

1.  它在伴随对象中定义了一个`newInstance()`方法。通过这样做，可以在不必创建`NewTaskDialogFragment`类的实例的情况下访问该方法。`newInstance()`方法执行以下操作：

+   它接受一个名为`title`的`Int`参数

+   它创建了`NewTaskDialogFragment`的一个实例，并将`title`作为其参数的一部分传递

+   返回`NewTaskDialogFragment`的新实例

1.  它重写了`onCreateDialog()`方法。此方法执行以下操作：

+   它尝试检索传递的标题参数

+   实例化`AlertDialog`构建器，并将检索到的标题分配为对话框的标题

+   它使用`DialogFragment`实例的父活动的`LayoutInflater`来填充我们创建的布局

+   然后，将充气的视图设置为对话框的视图

+   为对话框设置两个按钮：**保存**和**取消**

+   单击“保存”按钮时，将检索`EditText`中的文本，并通过`onDialogPositiveClick()`方法将其传递给`newTaskDialogListener`变量

1.  在`onAttach()`方法中，我们尝试将传递的`Activity`对象分配给前面创建的`newTaskDialogListener`变量。为使其工作，`Activity`对象应该实现`NewTaskDialogListener`接口。

现在，打开`MainActivity`类。更改类声明以包括`NewTaskDialogListener`的实现。您的类声明现在应该如下所示：

```kt
class MainActivity : AppCompatActivity(), NewTaskDialogFragment.NewTaskDialogListener {
```

并通过向`MainActivity`类添加以下方法来添加`NewTaskDialogListener`中声明的方法的实现：

```kt
    override fun onDialogPositiveClick(dialog: DialogFragment, task:String) {
    }

    override fun onDialogNegativeClick(dialog: DialogFragment) {
    }
```

在`showNewTaskUI()`方法中，添加以下代码行：

```kt
val newFragment = NewTaskDialogFragment.newInstance(R.string.add_new_task_dialog_title)
newFragment.show(fragmentManager, "newtask")
```

在上述代码行中，调用`NewTaskDialogFragment`中的`newInstance()`方法以生成`NewTaskDialogFragment`类的实例。然后调用`DialogFragment`的`show()`方法来显示对话框。

构建并运行。现在，当您单击添加按钮时，您应该在屏幕上看到一个对话框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/31c08b76-8868-4b45-bd13-093c4a3cf4f5.png)

您可能已经注意到，单击保存按钮时什么都没有发生。在`onDialogPositiveClick()`方法中，添加此处显示的代码行：

```kt
Snackbar.make(fab, "Task Added Successfully", Snackbar.LENGTH_LONG).setAction("Action", null).show()
```

正如我们可能记得的那样，这行代码在屏幕底部显示一个滚动消息。

构建并运行。现在，当您在**New Task**对话框上单击 SAVE 按钮时，屏幕底部会显示一个滚动消息。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/9b29319d-b505-4e02-80a7-263b354db26a.png)

我们目前没有存储用户输入的任务。让我们创建一个集合变量来存储用户添加的任何任务。在`MainActivity`类中，添加一个类型为`ArrayList<String>`的新变量，并用空的`ArrayList`进行实例化：

```kt
private var todoListItems = ArrayList<String>()
```

在`onDialogPositiveClick()`方法中，在方法定义的开头放置以下代码行：

```kt
todoListItems.add(task)
listAdapter?.notifyDataSetChanged()
```

这将向`todoListItems`数据添加传递给`listAdapter`的任务变量，并调用`notifyDataSetChanged()`来更新`ListView`。

保存数据很好，但是我们的`ListView`仍然是空的。让我们继续纠正这一点。

# 在 ListView 中显示数据

要对 XML 布局中的 UI 元素进行更改，您需要使用`findViewById()`方法来检索布局的`Activity`中元素的实例。这通常在`Activity`的`onCreate()`方法中完成。

打开`MainActivity.kt`，并在类顶部声明一个新的`ListView`实例变量：

```kt
private var listView: ListView? = null
```

接下来，使用布局中相应元素的`ListView`变量进行实例化。通过在`onCreate()`方法的末尾添加以下一行代码来完成此操作：

```kt
listView = findViewById(R.id.list_view)
```

在`ListView`中显示数据，您需要创建一个`Adapter`，并向其提供要显示的数据以及如何显示该数据的信息。根据您希望在`ListView`中显示数据的方式，您可以使用现有的 Android Adapters 之一，也可以创建自己的 Adapter。现在，我们将使用最简单的 Android Adapter 之一，`ArrayAdapter`。`ArrayAdapter`接受一个数组或项目列表，一个布局 ID，并根据传递给它的布局显示您的数据。

在`MainActivity`类中，添加一个新的变量，类型为`ArrayAdapter`：

```kt
private var listAdapter: ArrayAdapter<String>? = null

```

向类中添加此处显示的方法：

```kt
private fun populateListView() {
    listAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, todoListItems)
    listView?.adapter = listAdapter
}
```

在上述代码行中，我们创建了一个简单的`ArrayAdapter`并将其分配给`listView`作为其`Adapter`。

现在，在`onCreate()`方法中添加对前一个方法的调用：

```kt
populateListView()
```

构建并运行。现在，当您单击添加按钮时，您将看到您的条目显示在 ListView 上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b73860ce-65bb-40f3-abc2-89165565c842.png)

# 更新/删除待办事项

如果用户在输入新任务时出现错误怎么办？我们需要为他们提供一种能够编辑列表项或完全删除该项的方法。我们可以提供菜单项，仅在用户单击项目时显示。菜单项将为用户提供编辑或删除所选项的机会。

如果用户选择编辑选项，我们将显示我们的任务对话框，并为用户填写任务字段以进行所需的更改。

让我们首先向`strings.xml`资源文件添加以下一组字符串：

```kt
<string name="update_task_dialog_title">Edit Task</string>
<string name="edit">Edit</string>
<string name="delete">Delete</string>
```

接下来，我们需要在 UI 中添加一个菜单。

# 添加菜单

让我们首先创建菜单资源文件。右键单击`res`目录，然后选择 New | Android resource file。输入`to_do_list_menu`作为文件名。将资源类型更改为菜单，然后单击确定，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/3cb43c69-1053-4cae-b5a2-6808d8d04b79.png)

用以下代码替换`to_do_list_menu,xml`文件中的代码行：

```kt
<?xml version="1.0" encoding="utf-8"?>
<menu xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:android="http://schemas.android.com/apk/res/android">

    <item
        android:id="@+id/edit_item"
        android:title="@string/edit"
        android:icon="@android:drawable/ic_menu_edit"
        android:visible="false"
        app:showAsAction="always"/>
    <item
        android:id="@+id/delete_item"
        android:title="@string/delete"
        android:icon="@android:drawable/ic_menu_delete"
        android:visible="false"
        app:showAsAction="always"/>
</menu>
```

在上述代码行中，我们创建了两个菜单项，`edit`和`delete`项。我们还将每个菜单项的可见性设置为`false`。

接下来，打开`MainActivity`类，并在类顶部添加以下两个新变量：

```kt
private var showMenuItems = false
private var selectedItem = -1 
```

`showMenuItems`变量将用于跟踪菜单项的可见状态，而`selectedItem`变量存储当前选定列表项的位置。

然后，重写`onCreateOptionsMenu()`方法，如果`showMenuItems`变量设置为`true`，则启用菜单项：

```kt
override fun onCreateOptionsMenu(menu: Menu): Boolean {
    val inflater = menuInflater
    inflater.inflate(R.menu.to_do_list_menu, menu)
    val editItem = menu.findItem(R.id.edit_item)
    val deleteItem = menu.findItem(R.id.delete_item)

    if (showMenuItems) {
        editItem.isVisible = true
        deleteItem.isVisible = true
    }

    return true
}
```

接下来，打开`MainActivity`类，并添加以下方法：

```kt
private fun showUpdateTaskUI(selected: Int) {
    selectedItem = selected
    showMenuItems = true
    invalidateOptionsMenu()
}
```

当调用此方法时，它将分配传递给它的参数给`selectedItem`变量，并将`showMenuItems`的值更改为`true`。然后调用`invalidateOptionsMenu()`方法。`invalidateOptionsMenu()`方法通知操作系统已对`Activity`相关的菜单进行了更改。这将导致菜单被重新创建。

现在，我们需要为`ListView`实现一个`ItemClickListener`。在`onCreate()`方法中，添加以下代码行：

```kt
listView?.onItemClickListener = AdapterView.OnItemClickListener { parent, view, position, id -> showUpdateTaskUI(position) }

```

在这些代码行中，当单击项目时，将调用`showUpdateTaskUI()`方法。

再次构建和运行。这次，当您单击列表项时，菜单项将显示出来，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2cf76359-4b59-403e-b194-4f10618949b7.png)

接下来，我们需要更新`NewTaskDialogFragment`类以接受和处理所选任务。打开`NewTaskDialogFragment`类。

更新`newInstance()`方法以接受`String`类型的额外参数，并通过以下代码将该参数作为`DialogFragment`参数的一部分传递：

```kt
fun newInstance(title: Int, selected: String?): NewTaskDialogFragment { // 1
    val newTaskDialogFragment = NewTaskDialogFragment()
    val args = Bundle()
    args.putInt("dialog_title", title)
    args.putString("selected_item", selected) // 2
    newTaskDialogFragment.arguments = args
    return newTaskDialogFragment
}
```

**注意：**更改的地方标有数字。

接下来，更新`onCreateDialog()`方法以检索并显示所选任务的文本，如下面的代码所示：

```kt
override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
    val title = arguments.getInt("dialog_title")
    val selectedText = arguments.getString("selected_item") // 1
    val builder = AlertDialog.Builder(activity)
    builder.setTitle(title)

    val dialogView = activity.layoutInflater.inflate(R.layout.dialog_new_task, null)

    val task = dialogView.findViewById<EditText>(R.id.task)

    task.setText(selectedText)  // 2

    builder.setView(dialogView)
            .setPositiveButton(R.string.save, { dialog, id ->

                newTaskDialogListener?.onDialogPositiveClick(this, task.text.toString());
            })
            .setNegativeButton(android.R.string.cancel, { dialog, id ->

                newTaskDialogListener?.onDialogNegativeClick(this)
            })

    return builder.create()
}
```

接下来，我们需要实现当用户选择菜单项时的功能。这是通过重写`onOptionsItemSelected()`方法来完成的：

```kt
override fun onOptionsItemSelected(item: MenuItem?): Boolean {

if (-1 != selectedItem) {
if (R.id.edit_item == item?.itemId) {  // 1

val updateFragment = NewTaskDialogFragment.newInstance(R.string.update_task_dialog_title, todoListItems[selectedItem])
            updateFragment.show(fragmentManager, "updatetask")

        } else if (R.id.delete_item == item?.itemId) {  // 2

todoListItems.removeAt(selectedItem)
listAdapter?.notifyDataSetChanged()
selectedItem = -1
            Snackbar.make(fab, "Task deleted successfully", 
            Snackbar.LENGTH_LONG).setAction("Action", null).show()

        }
    }
return super.onOptionsItemSelected(item)
}
```

在上述方法中，检查所选菜单项的 ID 与两个菜单项的 ID 是否匹配。

1.  如果所选菜单项是编辑按钮：

+   生成并显示`NewTaskDialogFragment`的新实例。在生成新实例的调用中，检索并传递所选任务。

1.  如果是`delete`按钮：

+   所选项目从`todoListItems`中删除

+   通知`listAdapter`数据已更改

+   `selectedItem`变量被重置为-1

+   并且，将显示一个提示，通知用户删除成功删除

正如您可能已经注意到的，在调用`show()`方法时，第二个参数是一个`String`。这个参数是标签。标签充当一种 ID，用于区分`Activity`管理的不同片段。我们将使用标签来决定在调用`onDialogPositiveClick()`方法时执行哪些操作。

用以下方法替换`onDialogPositiveClick()`方法：

```kt
override fun onDialogPositiveClick(dialog: DialogFragment, task:String) {

    if("newtask" == dialog.tag) {
        todoListItems.add(task)
        listAdapter?.notifyDataSetChanged()

        Snackbar.make(fab, "Task Added Successfully", 
        Snackbar.LENGTH_LONG).setAction("Action", null).show()

    } else if ("updatetask" == dialog.tag) {
        todoListItems[selectedItem] = task

        listAdapter?.notifyDataSetChanged()

        selectedItem = -1

        Snackbar.make(fab, "Task Updated Successfully", 
        Snackbar.LENGTH_LONG).setAction("Action", null).show()
    }
}
```

在上述代码行中，以下内容适用：

1.  如果对话框的标签是`newtask`：

+   任务变量被添加到`todoListItems`数据中，并通知`listAdapter`更新`ListView`

+   还会显示一个提示，通知用户任务已成功添加

1.  如果对话框的标签是`updatetask`：

+   选定的项目用任务变量替换在`todoListItems`数据集中，并通知`listAdapter`更新`ListView`

+   `selectedItem`变量被重置为-1

+   此外，还会显示一个滚动消息通知用户任务已成功更改

构建并运行。选择一个任务并点击编辑菜单项。这将弹出编辑任务对话框，并自动填充所选任务的详细信息，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2ee0e7cf-f5d4-4785-ab26-c47f20307da4.png)

对任务详情进行更改，然后点击保存按钮。这将关闭对话框，更新您的`ListView`以显示更新后的任务，并在屏幕底部显示一个消息为“任务成功更新”的滚动消息，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/20a2ea4c-717a-47f0-9ba3-ac870b49430a.png)

接下来，选择一个任务并点击删除菜单项。这将删除所选的任务，并在屏幕底部显示一个消息为“任务成功删除”的滚动消息，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6d91962d-cf20-4d46-ba8a-fceeff7156b7.png)

# 摘要

在本章中，我们构建了一个简单的 TodoList 应用程序，允许用户添加新任务，并编辑或删除已添加的任务。在这个过程中，我们学会了如何使用 ListViews 和 Dialogs。在当前状态下，TodoList 应用程序在重新启动时会重置数据。这并不理想，因为用户很可能希望在重新启动应用程序后查看他们的旧任务。

在下一章中，我们将学习有关不同的数据存储选项以及如何使用它们来使我们的应用程序更加可用。我们将扩展 TodoList 应用程序以将用户的任务持久化到数据库中。


# 第十一章：使用数据库持久化

在本章中，我们将通过正确地将用户输入的任务持久化到数据库中，改进上一章的待办事项列表应用。

在本章中，我们将学习以下内容：

+   数据库的概念

+   移动开发可用的不同类型的数据库

+   如何连接到一些不同的可用数据库

# 数据库简介

数据库简单地是一组数据，以使访问和/或更新它变得容易的方式组织起来。组织数据可以以许多方式进行，但它们可以分为两种主要类型：

+   关系数据库

+   非关系数据库

# 关系数据库

关系数据库是一种根据数据之间的关系组织数据的数据库。在关系数据库中，数据以表格的形式呈现，有行和列。表格存储了相同类型的数据集合。表格中的每一列代表表格中存储的对象的属性。表格中的每一行代表一个存储的对象。表格有一个标题，指定了要存储在数据库中的对象的不同属性的名称和类型。在关系数据库中，每个属性的数据类型在创建表格时指定。

让我们来看一个例子。这里的表代表了一组学生：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/9cdfbeee-544f-46ce-8ee7-4ef1c80c7f57.jpg)

表的每一行代表一个学生。列代表每个学生的不同属性。

关系数据库是使用**RDBMS**（**关系数据库管理系统**）维护的。数据是使用一种称为**SQL**（结构化查询语言）的语言访问和管理的。一些最常用的 RDBMS 是 Oracle、MySQL、Microsoft SQL Server、PostgreSQL、Microsoft Access 和 SQLite。MySQL、PostgreSQL 和 SQLite 是开源的。

Android 开发的 RDBMS 选择是 SQLite。这是因为 Android 操作系统捆绑了 SQLite。

在上一章中，我们构建了一个待办事项列表应用，允许用户添加、更新和删除任务。我们使用了`ArrayList`作为我们的数据存储。让我们继续扩展应用程序，改用关系数据库。

# 使用 SQLite

首先要做的是定义数据库的架构。数据库的架构定义了数据库中的数据是如何组织的。它定义了数据组织到哪些表中，并对这些表的限制（例如列的允许数据类型）进行了定义。建议创建一个合同类，指定数据库的详细信息。

创建一个新的 Kotlin 对象，名为`TodoListDBContract`，并用以下代码替换其内容：

```kt
object TodoListDBContract {

        const val DATABASE_VERSION = 1
        const val DATABASE_NAME = "todo_list_db"

    class TodoListItem: BaseColumns {
        companion object {
            const val TABLE_NAME = "todo_list_item"
            const val COLUMN_NAME_TASK = "task_details"
            const val COLUMN_NAME_DEADLINE = "task_deadline"
            const val COLUMN_NAME_COMPLETED = "task_completed"
        }
    }

}
```

在上述代码中，`TodoListItem`类代表了我们数据库中的一个表，并用于声明表的名称和其列的名称。

要创建一个新的 Kotlin 对象，首先右键单击包，然后选择新建

| Kotlin 文件/类。然后在新的 Kotlin 文件/类对话框中，在`Kind`字段中选择`Object`：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/17843c5f-c75e-4ae4-a767-86b46ba915b2.png)

接下来要做的是创建一个数据库助手类。这将帮助我们抽象出对数据库的连接，并且不将数据库连接逻辑保留在我们的 Activity 中。继续创建一个名为`TodoListDBHelper`的新的 Kotlin 类。该类应该在其默认构造函数中接受一个`Context`参数，并扩展`android.database.sqlite.SQLiteOpenHelper`类，如下所示：

```kt
class TodoListDBHelper(context: Context): SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {
```

现在，按照以下代码将以下代码添加到`TodoListDBHelper`类中：

```kt
private val SQL_CREATE_ENTRIES = "CREATE TABLE " + TodoListDBContract.TodoListItem.TABLE_NAME + " (" +
        BaseColumns._ID + " INTEGER PRIMARY KEY AUTOINCREMENT," +
        TodoListDBContract.TodoListItem.COLUMN_NAME_TASK + " TEXT, " +
        TodoListDBContract.TodoListItem.COLUMN_NAME_DEADLINE + " TEXT, " +
        TodoListDBContract.TodoListItem.COLUMN_NAME_COMPLETED + " INTEGER)"  // 1

private val SQL_DELETE_ENTRIES = "DROP TABLE IF EXISTS " + TodoListDBContract.TodoListItem.TABLE_NAME   // 2

override fun onCreate(db: SQLiteDatabase) { // 3
 db.execSQL(SQL_CREATE_ENTRIES)
}

override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {// 4
 db.execSQL(SQL_DELETE_ENTRIES)
 onCreate(db)
}

override fun onDowngrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
 onUpgrade(db, oldVersion, newVersion)
}
```

在上述代码中，以下内容适用：

+   `SQL_CREATE_ENTRIES`是一个 SQL 查询，用于创建一个表。它指定了一个`_id`字段，该字段被设置为数据库的主键。

在关系数据库中，表需要有一个列来唯一标识每个行条目。这个唯一的列被称为**主键**。将列指定为**AUTOINCREMENT**告诉 RDBMS 在插入新行时自动生成此字段的新值。

+   `SQL_DELETE_ENTRIES`是一个 SQL 查询，用于删除表（如果存在）。

+   在`onCreate()`方法中，执行 SQL 查询以创建表。

+   在`onUpgrade()`中，表被删除并重新创建。

由于表在数据库中将有一个 ID 字段，我们必须在`Task`类中添加一个额外的字段来跟踪它。打开`Task.kt`，添加一个名为`taskId`的`Long`类型的新字段。

```kt
var taskId: Long? = null
```

接下来，添加如下所示的构造函数：

```kt
constructor(taskId:Long, taskDetails: String?, taskDeadline: String?, completed: Boolean) : this(taskDetails, taskDeadline) {
        this.taskId = taskId
        this.completed = completed
    }
```

# 将数据插入数据库

打开`TodoListDBHelper`，并添加以下所示的方法：

```kt
fun addNewTask(task: Task): Task {
        val db = this.writableDatabase // 1

// 2
        val values = ContentValues()
        values.put(TodoListDBContract.TodoListItem.COLUMN_NAME_TASK, task.taskDetails)
        values.put(TodoListDBContract.TodoListItem.COLUMN_NAME_DEADLINE, task.taskDeadline)
        values.put(TodoListDBContract.TodoListItem.COLUMN_NAME_COMPLETED, task.completed)

        val taskId = db.insert(TodoListDBContract.TodoListItem.TABLE_NAME, null, values); // 3
        task.taskId = taskId

        return task
    }
```

在这里，我们执行以下操作：

1.  我们首先以写模式检索数据库。

1.  接下来，我们创建一个`ContentValues`的实例，并放入我们要插入的项目中字段的值键映射。

1.  然后，我们在数据库对象上调用`insert()`方法，将表名和`ContentValues`实例传递给它。这将返回插入项的主键`_id`。我们更新任务对象并返回它。

打开`MainActivity`类。

首先，在类的顶部添加`TodoListDBHelper`类的一个实例作为一个新字段：

```kt
private var dbHelper: TodoListDBHelper = TodoListDBHelper(this)
```

并重写`AppCompatActivity`的`onDestroy()`方法：

```kt
override fun onDestroy() {
    dbHelper.close()
    super.onDestroy()
}
```

当 Activity 的`onDestroy()`方法被调用时，这将关闭数据库连接。

然后，在`onDialogPositiveClick()`方法中，找到这行代码：

```kt
todoListItems.add(Task(taskDetails, ""))
```

用以下代码替换它：

```kt
val addNewTask = dbHelper.addNewTask(Task(taskDetails, ""))
todoListItems.add(addNewTask)
```

调用`dbHelper.addNewTask()`将新任务保存到数据库，而不仅仅是将其添加到`todoListItems`字段中。

构建并运行应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2db33716-0630-4e2d-a312-b6266e3502d0.png)

既然我们已经能够保存到数据库，我们需要在应用程序启动时能够查看数据。

# 从数据库中检索数据

打开`TodoListDBHelper`，并添加如下所示的方法：

```kt
fun retrieveTaskList(): ArrayList<Task> {
    val db = this.readableDatabase  // 1

    val projection = arrayOf<String>(BaseColumns._ID,
            TodoListDBContract.TodoListItem.COLUMN_NAME_TASK,
            TodoListDBContract.TodoListItem.COLUMN_NAME_DEADLINE,
            TodoListDBContract.TodoListItem.COLUMN_NAME_COMPLETED) // 2

    val cursor = db.query(TodoListDBContract.TodoListItem.TABLE_NAME, projection, 
            null, null, null, null, null) // 3

    val taskList = ArrayList<Task>()
// 4
    while (cursor.moveToNext()) {
        val task = Task(cursor.getLong(cursor.getColumnIndexOrThrow(BaseColumns._ID)),
                cursor.getString(cursor.getColumnIndexOrThrow(TodoListDBContract.TodoListItem.COLUMN_NAME_TASK)),
                cursor.getString(cursor.getColumnIndexOrThrow(TodoListDBContract.TodoListItem.COLUMN_NAME_DEADLINE)),
                cursor.getInt(cursor.getColumnIndexOrThrow(TodoListDBContract.TodoListItem.COLUMN_NAME_COMPLETED)) == 1)
        taskList.add(task)
    }
    cursor.close() // 5

    return taskList
}
```

在`retrieveTaskList`方法中，我们执行以下操作：

1.  我们首先以读模式检索数据库。

1.  接下来，我们创建一个列出我们需要检索的表的所有列的数组。在这里，如果我们不需要特定列的值，我们就不添加它。

1.  然后，我们将表名和列列表传递给数据库对象上的`query()`方法。这将返回一个`Cursor`对象。

1.  接下来，我们循环遍历`Cursor`对象中的项目，并使用每个项目的属性创建`Task`类的实例。

1.  我们关闭游标并返回检索到的数据

现在，打开`MainActivity`，并在`populateListView()`方法的开头添加以下代码行：

```kt
    todoListItems = dbHelper.retrieveTaskList();
```

您的`populateListView()`方法现在应该如下所示：

```kt
private fun populateListView() {
    todoListItems = dbHelper.retrieveTaskList();
    listAdapter = TaskListAdapter(this, todoListItems)
    listView?.adapter = listAdapter
}
```

现在，重新构建并运行。您会注意到，与上一章不同的是，当您重新启动应用程序时，您之前保存的任务会被保留：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b24d7315-a1a7-436d-95e9-4b8aa4b26542.png)

# 更新任务

在本节中，我们将学习如何更新数据库中已保存任务的详细信息。打开`TodoListDBHelper`，并添加如下所示的方法：

```kt
    fun updateTask(task: Task) {
        val db = this.writableDatabase // 1

        // 2
        val values = ContentValues()
        values.put(TodoListDBContract.TodoListItem.COLUMN_NAME_TASK, task.taskDetails)
        values.put(TodoListDBContract.TodoListItem.COLUMN_NAME_DEADLINE, task.taskDeadline)
        values.put(TodoListDBContract.TodoListItem.COLUMN_NAME_COMPLETED, task.completed)

        val selection = BaseColumns._ID + " = ?" // 3
        val selectionArgs = arrayOf(task.taskId.toString()) // 4

        db.update(TodoListDBContract.TodoListItem.TABLE_NAME, values, selection, selectionArgs) // 5

    }
```

在`updateTask()`方法中，我们执行以下操作：

1.  我们首先以写模式检索数据库。

1.  接下来，我们创建一个`ContentValues`的实例，并放入我们要更新的字段的值键映射。对于我们正在处理的内容，我们将假定更新所有列。

1.  我们为选择要更新的数据库条目指定一个查询。我们的选择查询使用`_id`列。

1.  然后，我们为选择查询指定参数，这里，我们选择的是所选`Task`的`taskId`。

1.  然后，我们在数据库对象上调用`update()`方法，传递表名、`ContentValues`实例、选择查询和选择值。

在`MainActivity`类的`onDialogPositiveClick()`方法中，找到这行代码：

```kt
dbHelper.updateTask(todoListItems[selectedItem])
```

并将其放在以下代码行之后：

```kt
todoListItems[selectedItem].taskDetails = taskDetails
```

`onDialogPositiveClick()`方法现在应该如下所示：

```kt
override fun onDialogPositiveClick(dialog: DialogFragment, taskDetails:String) {
        if("newtask" == dialog.tag) {
            val addNewTask = dbHelper.addNewTask(Task(taskDetails, ""))
            todoListItems.add(addNewTask)
            listAdapter?.notifyDataSetChanged()

            Snackbar.make(fab, "Task Added Successfully", Snackbar.LENGTH_LONG).setAction("Action", null).show()

        } else if ("updatetask" == dialog.tag) {
            todoListItems[selectedItem].taskDetails = taskDetails
            dbHelper.updateTask(todoListItems[selectedItem])

            listAdapter?.notifyDataSetChanged()

            selectedItem = -1

            Snackbar.make(fab, "Task Updated Successfully", Snackbar.LENGTH_LONG).setAction("Action", null).show()
        }
    }
```

接下来，在`onOptionsItemSelected()`中，找到以下代码行：

```kt
dbHelper.updateTask(todoListItems[selectedItem])
```

然后，在此代码行之后放置：

```kt
todoListItems[selectedItem].completed = true
```

构建并运行。当您点击**标记为完成**菜单项时，所选任务将被更新为已完成，并相应地更新 listView：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a5216fb5-982a-43ff-89b2-a235647f803a.png)

# 删除任务

在本节中，我们将学习如何从数据库中删除已保存的任务。打开`TodoListDBHelper`，并添加以下方法：

```kt
    fun deleteTask(task:Task) {
        val db = this.writableDatabase // 1
        val selection = BaseColumns._ID + " = ?" // 2
        val selectionArgs = arrayOf(task.taskId.toString()) // 3
        db.delete(TodoListDBContract.TodoListItem.TABLE_NAME, selection, selectionArgs) // 4
    }
```

删除的过程类似于更新的过程：

1.  首先，以写模式检索数据库

1.  接下来，为选择要删除的数据库条目指定一个查询。我们的`selection`查询使用`_id`列

1.  然后，指定`selection`查询的参数，在我们的情况下是所选`Task`的`taskId`

1.  然后，我们在数据库对象上调用`delete()`方法，将表名、选择查询和选择值传递给它

在`MainActivity`类中的方法中，找到以下代码行：

```kt
todoListItems.removeAt(selectedItem)
```

用以下代码替换它：

```kt
val selectedTask = todoListItems[selectedItem]
todoListItems.removeAt(selectedItem)
dbHelper.deleteTask(selectedTask)
```

构建并运行。当您添加一个新项目时，该条目不仅会添加到`ListView`中，还会保存在数据库中：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/5ac315e8-e5d1-4094-ba24-3a5d1d6bdf0c.png)

编写自己的 SQL 查询可能会出错，特别是如果您正在构建一个严重依赖于数据库或需要非常复杂查询的应用程序。这也需要大量的努力和 SQL 查询知识。为了帮助解决这个问题，您可以使用 ORM 库。

# ORM 库

**ORM**（对象关系映射）库提供了一种更好的方式，让您将对象持久化到数据库中，而不用太担心 SQL 查询，以及打开和关闭数据库连接。

**注意**：您仍然需要一定水平的 SQL 查询知识

有许多适用于 Android 的 ORM 库：

+   ORMLite

+   GreenDAO

+   DbFlow

+   Room

但是，在本书中，我们将专注于 Room，这是 Google 推出的 ORM。

要使用 Room，我们首先必须将其依赖项添加到项目中。

打开`build.gradle`，并在依赖项部分添加以下代码行：

```kt
implementation 'android.arch.persistence.room:runtime:1.0.0'
annotationProcessor 'android.arch.persistence.room:compiler:1.0.0'
kapt "android.arch.persistence.room:compiler:1.0.0"
```

点击立即同步。为了让 Room 能够将任务保存到数据库中，我们需要指定哪个类表示一个表。这是通过将类注释为`Entity`来完成的。打开`Task`类，并用以下代码替换其内容：

```kt
@Entity(tableName = TodoListDBContract.TodoListItem.TABLE_NAME)
class Task() {

    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = BaseColumns._ID)
    var taskId: Long? = null

    @ColumnInfo(name = TodoListDBContract.TodoListItem.COLUMN_NAME_TASK)
    var taskDetails: String? = null

    @ColumnInfo(name = TodoListDBContract.TodoListItem.COLUMN_NAME_DEADLINE)
    var taskDeadline: String? = null

    @ColumnInfo(name = TodoListDBContract.TodoListItem.COLUMN_NAME_COMPLETED)
    var completed: Boolean? = false

    @Ignore
    constructor(taskDetails: String?, taskDeadline: String?): this() {
        this.taskDetails = taskDetails
        this.taskDeadline = taskDeadline
    }

    constructor(taskId:Long, taskDetails: String?, taskDeadline: String?, completed: Boolean) : this(taskDetails, taskDeadline) {
        this.taskId = taskId
        this.completed = completed
    }

}
```

在这里，以下内容适用：

+   `@Entity`指定`Task`表示数据库中的一个表

+   `@ColumnInfo`将字段映射到数据库列

+   `@PrimaryKey`指定该字段是表的主键

接下来是创建一个**DAO**（数据访问对象）。创建一个名为`TaskDAO`的新的 Kotlin 接口，并用以下代码替换其内容：

```kt
@Dao
interface TaskDAO {

    @Query("SELECT * FROM " + TodoListDBContract.TodoListItem.TABLE_NAME)
    fun retrieveTaskList(): List<Task> 

    @Insert
    fun addNewTask(task: Task): Long   

    @Update
    fun updateTask(task: Task)  

     @Delete
     fun deleteTask(task: Task)  

}
```

如前面的代码所示，以下内容适用：

+   Room 提供了`Insert`、`Update`和`Delete`注释，因此您不必为这些编写查询

+   对于选择操作，您必须使用查询注释方法

接下来，我们需要创建一个数据库类，将我们的应用程序连接到数据库。创建一个名为`AppDatabase`的新的 Kotlin 类，并用以下代码替换其内容：

```kt
@Database(entities = arrayOf(Task::class), version = TodoListDBContract.DATABASE_VERSION)
abstract class AppDatabase : RoomDatabase() {
    abstract fun taskDao(): TaskDAO
}
```

这就是连接到数据库所需的所有设置。

要使用数据库，打开`MainActivity`。首先，创建一个`AppDatabase`类型的字段：

```kt
private var database: AppDatabase? = null
```

接下来，在`onCreate()`方法中实例化字段：

```kt
database = Room.databaseBuilder(applicationContext, AppDatabase::class.java, DATABASE_NAME).build()
```

在这里，您指定了您的数据库类和数据库的名称。

# 从数据库中检索数据

Room 不允许您在主线程上运行数据库操作，因此我们将使用`AsyncTask`来执行调用。将此私有类添加到`MainActivity`类中，如前面的代码所示：

```kt
private class RetrieveTasksAsyncTask(private val database: AppDatabase?) : AsyncTask<Void, Void, List<Task>>() {

    override fun doInBackground(vararg params: Void): List<Task>? {
        return database?.taskDao()?.retrieveTaskList()
    }
}
```

在这里，我们在`doInBackground()`方法中调用`taskDao`来从数据库中检索任务列表。

接下来，在`populateListView()`方法中，找到以下代码行：

```kt
todoListItems = dbHelper.retrieveTaskList();
```

然后，用这个替换它：

```kt
todoListItems = RetrieveTasksAsyncTask(database).execute().get() as ArrayList<Task>
```

Room 创建并管理一个主表，用于跟踪数据库的版本。因此，即使我们需要对数据库进行迁移以保留当前数据库中的数据。

打开`TodoListDBContract`类，并将`DATABASE_VERSION`常量增加到`2`。

然后，用以下代码替换`MainActivity`中的数据库实例化：

```kt
database = Room.databaseBuilder(applicationContext, AppDatabase::class.java, DATABASE_NAME)
        .addMigrations(object : Migration(TodoListDBContract.DATABASE_VERSION - 1, TodoListDBContract.DATABASE_VERSION) {
            override fun migrate(database: SupportSQLiteDatabase) {
            }
        }).build()
```

在这里，我们向`databaseBuilder`添加一个新的`Migration`对象，同时指定数据库的当前版本和新版本。

现在，构建并运行。您的应用程序将启动，并显示先前保存的`Tasks`：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/437ab9e1-546d-4ee5-a647-fcc44f0d4004.png)

# 将数据插入数据库

要添加新任务，在`MainActivity`中创建一个新的`AsyncTask`：

```kt
private class AddTaskAsyncTask(private val database: AppDatabase?, private val newTask: Task) : AsyncTask<Void, Void, Long>() {

    override fun doInBackground(vararg params: Void): Long? {
        return database?.taskDao()?.addNewTask(newTask)
    }
}
```

在这里，我们在`doInBackground()`方法中调用`taskDao`来将新任务插入数据库。

接下来，在`onDialogPositiveClick()`方法中，找到以下代码行：

```kt
val addNewTask = dbHelper.addNewTask(Task(taskDetails, ""))
```

并用以下代码替换它：

```kt
var addNewTask = Task(taskDetails, "")

addNewTask.taskId = AddTaskAsyncTask(database, addNewTask).execute().get()
```

现在，构建并运行。就像在上一节中一样，当您添加新项目时，该条目不仅会添加到`ListView`中，还会保存到数据库中：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/0a374130-64f6-4d3b-b2e5-bfa9c68fa19e.png)

# 更新任务

要更新任务，在`MainActivity`中创建一个新的`AsyncTask`：

```kt
private class UpdateTaskAsyncTask(private val database: AppDatabase?, private val selectedTask: Task) : AsyncTask<Void, Void, Unit>() {

    override fun doInBackground(vararg params: Void): Unit? {
        return database?.taskDao()?.updateTask(selectedTask)
    }
}
```

在这里，我们在`doInBackground()`方法中调用`taskDao`来将新任务插入数据库。

接下来，在`onDialogPositiveClick()`方法中，找到以下代码行：

```kt
dbHelper.updateTask(todoListItems[selectedItem])
```

用这行代码替换它：

```kt
UpdateTaskAsyncTask(database, todoListItems[selectedItem]).execute()
```

此外，在`onOptionsItemSelected()`中，找到以下代码行：

```kt
dbHelper.updateTask(todoListItems[selectedItem])
```

并用这行代码替换它：

```kt
UpdateTaskAsyncTask(database, todoListItems[selectedItem]).execute()
```

现在，构建并运行。就像在上一章中一样，选择一个任务，然后单击编辑菜单项。在弹出的编辑任务对话框中，更改任务详细信息，然后单击“保存”按钮。

这将关闭对话框，保存对数据库的更改，更新您的 ListView 以显示更新后的任务，并在屏幕底部显示一个消息提示，显示任务已成功更新：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4db5afbc-4728-4d11-bf8b-9b71a1ce8345.png)

# 删除任务

要删除任务，在`MainActivity`中创建一个新的`AsyncTask`：

```kt
private class DeleteTaskAsyncTask(private val database: AppDatabase?, private val selectedTask: Task) : AsyncTask<Void, Void, Unit>() {

    override fun doInBackground(vararg params: Void): Unit? {
        return database?.taskDao()?.deleteTask(selectedTask)
    }
}
```

接下来，在`onOptionsItemSelected()`中，找到以下代码行：

```kt
dbHelper.deleteTask(selectedTask)
```

用这行代码替换它：

```kt
DeleteTaskAsyncTask(database, selectedTask).execute()
```

构建并运行。选择一个任务，然后单击删除菜单项。这将从 ListView 中删除所选任务，并从数据库中删除它，并在屏幕底部显示一个消息提示，显示任务已成功删除：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/01e114b6-5787-42ac-b0cc-a6c7a10d0fd7.png)

就是这样。正如您所看到的，使用 ORM 可以让您编写更少的代码并减少 SQL 错误。

# 非关系数据库

非关系型数据库，或者 NoSQL 数据库，是一种不基于关系组织数据的数据库。与关系数据库不同，不同的非关系数据库存储和管理数据的方式各不相同。一些将数据存储为键值对，而其他一些将数据存储为对象。其中许多选项支持 Android。在大多数情况下，这些数据库具有将数据同步到在线服务器的能力。最流行的两种 No-SQL 移动数据库是：

+   CouchBase Mobile

+   Realm

CouchBase 是文档数据库的一个例子，Realm 是对象数据库的一个例子。

文档数据库是无模式的，这意味着它们是非结构化的，因此对文档中可以放入什么没有限制。它们将数据存储为键值对。

另一方面，对象数据库将数据存储为对象。

# 总结

在本章中，我们添加了将任务存储到数据库的功能。我们还了解了可以使用的不同类型的数据库。在 Android 开发人员中使用最多的数据库是 SQLite，但这并不妨碍您探索其他选项。还有一些数据库服务，如 Firebase，提供后端作为服务的功能。

在选择数据库时，您应该考虑应用程序的数据需求。是否需要将数据存储在在线服务器上？还是，这些数据仅在应用程序的实例中本地使用？您是否想要或有能力设置和管理自定义数据服务器，还是您更愿意选择一个为您完成这项工作的服务？这些都是在为您的 Android 应用程序选择数据库时需要考虑的一些因素。

在下一章中，我们将致力于为我们的待办事项列表应用程序添加提醒功能。
