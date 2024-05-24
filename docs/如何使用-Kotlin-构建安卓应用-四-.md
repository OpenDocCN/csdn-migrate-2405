# 如何使用 Kotlin 构建安卓应用（四）

> 原文：[`zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295`](https://zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Android 权限和 Google 地图

概述

本章将为您提供如何在 Android 中请求和获取应用程序权限的知识。您将深入了解如何在应用程序中包含本地和全局交互地图，以及如何请求使用 Google Maps API 提供更丰富功能的设备功能的权限。

在本章结束时，您将能够为您的应用程序创建权限请求并处理缺失的权限。

# 介绍

在上一章中，我们学习了如何使用`RecyclerView`在列表中呈现数据。我们利用这些知识向用户展示了一个秘密猫特工列表。在本章中，我们将学习如何在地图上找到用户的位置，以及如何通过在地图上选择位置来部署猫特工。

首先，我们将研究 Android 权限系统。许多 Android 功能对我们来说并不是立即可用的。为了保护用户，这些功能被放在权限系统的后面。为了访问这些功能，我们必须请求用户允许我们这样做。一些这样的功能包括但不限于获取用户的位置，访问用户的联系人，访问他们的相机，以及建立蓝牙连接。不同的 Android 版本实施不同的权限规则。例如，当 2015 年引入 Android 6（Marshmallow）时，一些权限被认为是不安全的（您可以在安装时悄悄获得）并成为运行时权限。

接下来我们将看一下 Google Maps API。这个 API 允许我们向用户展示任何所需位置的地图，向地图添加数据，并让用户与地图进行交互。它还可以让你显示感兴趣的点，并在支持的位置呈现街景，尽管在本书中我们不会涉及这些功能。

# 向用户请求权限

我们的应用程序可能希望实现一些被 Google 认为是危险的功能。这通常意味着访问这些功能可能会危及用户的隐私。例如，这些权限可能允许您读取用户的消息或确定他们当前的位置。

根据特定权限和我们正在开发的目标 Android API 级别，我们可能需要向用户请求该权限。如果设备运行在 Android 6（Marshmallow，或 API 级别 23）上，并且我们应用的目标 API 是 23 或更高，几乎肯定会是这样，因为现在大多数设备都会运行更新版本的 Android，那么在安装时不会有用户通知警告用户应用程序请求的任何权限。相反，我们的应用必须在运行时要求用户授予它这些权限。

当我们请求权限时，用户会看到一个对话框，类似于以下截图所示：

![图 7.1 设备位置访问权限对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_01.jpg)

图 7.1 设备位置访问权限对话框

注意

有关权限及其保护级别的完整列表，请参见这里：[`developer.android.com/reference/android/Manifest.permission`](https://developer.android.com/reference/android/Manifest.permission)

当我们打算使用某个权限时，我们必须在清单文件中包含该权限。具有`SEND_SMS`权限的清单将类似于以下代码片段：

```kt
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.snazzyapp">
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <application ...>
...
    </application>
</manifest>
```

安全权限（或正常权限，如 Google 所称）将自动授予用户。然而，危险权限只有在用户明确批准的情况下才会被授予。如果我们未能向用户请求权限并尝试执行需要该权限的操作，结果最好是该操作不会运行，最坏的情况是我们的应用程序崩溃。

要向用户请求权限，我们应该首先检查用户是否已经授予我们该权限。

如果用户尚未授予我们权限，我们可能需要检查是否需要在请求权限之前显示理由对话框。这取决于请求的理由对用户来说是否显而易见。例如，如果相机应用请求访问相机的权限，我们可以安全地假设用户会清楚理由。然而，有些情况对用户来说可能不那么清晰，特别是如果用户不精通技术。在这些情况下，我们可能需要向用户解释请求的理由。Google 为我们提供了一个名为`shouldShowRequestPermissionRationale(Activity, String)`的函数来实现这个目的。在幕后，这个函数检查用户是否先前拒绝了权限，但也检查用户是否在权限请求对话框中选择了`不再询问`。这个想法是给我们一个机会，在请求之前向用户解释我们请求权限的理由，从而增加他们批准的可能性。

一旦我们确定是否应向用户呈现权限理由，或者用户是否应接受我们的理由或者不需要理由，我们就可以继续请求权限。

让我们看看如何请求权限。

我们请求权限的`Activity`类必须实现`OnRequestPermissionsResultCallback`接口。这是因为一旦用户被授予（或拒绝）权限，将调用`onRequestPermissionsResult(Int, Array<String>, IntArray)`函数。`FragmentActivity`类，`AppCompatActivity`扩展自它，已经实现了这个接口，所以我们只需要重写`onRequestPermissionsResult`函数来处理用户对权限请求的响应。以下是一个请求`Location`权限的`Activity`类的示例：

```kt
private const val PERMISSION_CODE_REQUEST_LOCATION = 1
class MainActivity : AppCompatActivity() {
    override fun onResume() {
        ...
        val hasLocationPermissions = getHasLocationPermission()
    }
```

当我们的`Activity`类恢复时，我们通过调用`getHasLocationPermissions()`来检查我们是否有位置权限（`ACCESS_FINE_LOCATION`）：

```kt
    private fun getHasLocationPermission() = if (
        ContextCompat.checkSelfPermission(
            this, Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
    ) {
        true
    } else {
        if (ActivityCompat.shouldShowRequestPermissionRationale(
                this, Manifest.permission.ACCESS_FINE_LOCATION
            )
        ) {
            showPermissionRationale { requestLocationPermission() }
        } else {
            requestLocationPermission()
        }
        false
    }
```

这个函数首先通过调用`checkSelfPermission(Context, String)`来检查用户是否已经授予了我们请求的权限。如果用户没有授予，我们调用我们之前提到的`shouldShowRequestPermissionRationale(Activity, String)`来检查是否应向用户呈现理由对话框。

如果需要显示我们的理由，我们调用`showPermissionRationale(() -> Unit)`，传入一个在用户关闭我们的理由对话框后将调用`requestLocationPermission()`的 lambda。如果不需要理由，我们直接调用`requestLocationPermission()`：

```kt
    private fun showPermissionRationale(positiveAction: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("Location permission")
            .setMessage("We need your permission to find               your current position")
            .setPositiveButton(
                "OK"
            ) { _, _ -> positiveAction() }
            .create()
            .show()
    }
```

我们的`showPermissionRationale`函数简单地向用户呈现一个对话框，简要解释为什么我们需要他们的权限。确认按钮将执行积极的操作：

![图 7.2 理由对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_02.jpg)

图 7.2 理由对话框

```kt
    private fun requestLocationPermission() {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION
            ),
            PERMISSION_CODE_REQUEST_LOCATION
        )
    }
```

最后，我们的`requestLocationPermission()`函数调用`requestPermissions(Activity, Array<out String>, Int)`，向我们的活动传递一个包含请求的权限和我们独特的请求代码的数组。我们将使用这个代码来稍后识别响应属于这个请求。

如果我们已经向用户请求了位置权限，现在我们需要处理响应。这是通过重写`onRequestPermissionsResult(Int, Array<out String>, IntArray)`函数来完成的，如下面的代码所示：

```kt
override fun onRequestPermissionsResult(
    requestCode: Int,
    permissions: Array<out String>,
    grantResults: IntArray
) {
    super.onRequestPermissionsResult(requestCode, permissions, 
      grantResults)
    when (requestCode) {
        PERMISSION_CODE_REQUEST_LOCATION -> getLastLocation()
    }
}
```

当`onRequestPermissionsResult`被调用时，会传入三个值。第一个是请求代码，将与我们调用`requestPermissions`时提供的请求代码相同。第二个是请求的权限数组。第三个是我们请求的结果数组。对于每个请求的权限，这个数组将包含`PackageManager.PERMISSION_GRANTED`或`PackageManager.PERMISSION_DENIED`。

本章将带领我们开发一个应用程序，在地图上显示我们当前的位置，并允许我们在想要部署我们的秘密猫特工的地方放置一个标记。让我们从我们的第一个练习开始。

## 练习 7.01：请求位置权限

在这个练习中，我们将请求用户提供位置权限。我们将首先创建一个 Google Maps Activity 项目。我们将在清单文件中定义所需的权限。让我们开始实现所需的代码，以请求用户访问其位置的权限：

1.  首先创建一个新的 Google Maps Activity 项目（`文件` | `新建` | `新项目` | `Google Maps Activity`）。在这个练习中我们不会使用 Google Maps。然而，在这种情况下，Google Maps Activity 仍然是一个不错的选择。它将在下一个练习（*练习 7.02*）中为你节省大量样板代码。不用担心；这不会对你当前的练习产生影响。点击`下一步`，如下截图所示：![图 7.3：选择你的项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_03.jpg)

图 7.3：选择你的项目

1.  将你的应用程序命名为`Cat Agent Deployer`。

1.  确保你的包名是`com.example.catagentdeployer`。

1.  将保存位置设置为你想要保存项目的位置。

1.  将其他所有内容保持默认值，然后点击`完成`。

1.  确保你的`Project`窗格中处于`Android`视图：![图 7.4：Android 视图](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_04.jpg)

图 7.4：Android 视图

1.  打开你的`AndroidManifest.xml`文件。确保位置权限已经添加到你的应用程序中：

```kt
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.catagentdeployer">
    ACCESS_FINE_LOCATION is the permission you will need to obtain the user's location based on GPS in addition to the less accurate Wi-Fi and mobile data-based location information you could obtain by using the ACCESS_COARSE_LOCATION permission.
```

1.  打开你的`MapsActivity.kt`文件。在`MapsActivity`类块的底部添加一个空的`getLastLocation()`函数：

```kt
class MapsActivity : AppCompatActivity(), OnMapReadyCallback {
    ...
    private fun getLastLocation() {
 Log.d("MapsActivity", "getLastLocation() called.")
    }
}
```

这将是当你确保用户已经授予了位置权限时你将调用的函数。

1.  接下来，在文件顶部的导入和类定义之间添加请求代码常量：

```kt
...
import com.google.android.gms.maps.model.MarkerOptions
private const val PERMISSION_CODE_REQUEST_LOCATION = 1
class MapsActivity : AppCompatActivity(), OnMapReadyCallback {
```

这将是我们在请求位置权限时传递的代码。无论我们在这里定义什么值，当用户完成与请求对话框的交互并授予或拒绝我们权限时，都将返回给我们。

1.  现在在`getLastLocation()`函数之前添加`requestLocationPermission()`函数：

```kt
private fun requestLocationPermission() {
    ActivityCompat.requestPermissions(
        this,
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),
        PERMISSION_CODE_REQUEST_LOCATION
    )
}
private fun getLastLocation() {
    ...
}
```

这个函数将向用户呈现一个标准的权限请求对话框（如下图所示），要求他们允许应用程序访问他们的位置。我们传递了将接收回调的活动（`this`），你希望用户授予你的应用程序的请求权限的数组（`Manifest.permission.ACCESS_FINE_LOCATION`），以及你刚刚定义的`PERMISSION_CODE_REQUEST_LOCATION`常量，以将其与权限请求关联起来：

![图 7.5：权限对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_05.jpg)

图 7.5：权限对话框

1.  重写你的`MapsActivity`类的`onRequestPermissionsResult(Int, Array<String>, IntArray)`函数：

```kt
override fun onRequestPermissionsResult(
    requestCode: Int, permissions: Array<out String>,       grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode,           permissions,grantResults)
    when (requestCode) {
            PERMISSION_CODE_REQUEST_LOCATION -> if (
                grantResults[0] == PackageManager.PERMISSION_GRANTED
            ) {
                getLastLocation()
            }
    }
}
```

你应该首先调用 super 实现（当你重写函数时，这应该已经为你完成）。这将处理权限响应处理的委托给相关的子片段。

然后，你可以检查`requestCode`参数，看看它是否与你传递给`requestPermissions(Activity, Array<out String>, Int)`函数的`requestCode`参数匹配（`PERMISSION_CODE_REQUEST_LOCATION`）。如果匹配，由于你知道你只请求了一个权限，你可以检查第一个`grantResults`值。如果它等于`PackageManager.PERMISSION_GRANTED`，则用户已经授予了你的应用程序权限，你可以通过调用`getLastLocation()`来继续获取他们的最后位置。

1.  如果用户拒绝了你的应用程序请求的权限，你可以向他们提出请求的理由。在`requestLocationPermission()`函数之前实现`showPermissionRationale(() -> Unit)`函数：

```kt
private fun showPermissionRationale(positiveAction: () -> Unit) {
    AlertDialog.Builder(this)
        .setTitle("Location permission")
        .setMessage("This app will not work without knowing your           current location")
        .setPositiveButton(
            "OK"
        ) { _, _ -> positiveAction() }
        .create()
        .show()
}
```

此函数将向用户呈现一个简单的警报对话框，解释应用程序如果不知道其当前位置将无法工作，如下截图所示。单击“确定”将执行提供的`positiveAction` lambda：

![图 7.6：理由对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_06.jpg)

图 7.6：理由对话框

1.  添加所需的逻辑来确定是显示权限请求对话框还是理由对话框。在`showPermissionRationale(() -> Unit)`函数之前创建`requestPermissionWithRationaleIfNeeded()`函数：

```kt
private fun requestPermissionWithRationaleIfNeeded() = if (
    ActivityCompat.shouldShowRequestPermissionRationale(
        this, Manifest.permission.ACCESS_FINE_LOCATION
    )
) {
    showPermissionRationale {
        requestLocationPermission()
    }
} else {
    requestLocationPermission()
}
```

此函数检查您的应用程序是否应显示理由对话框。如果应该，它将调用`showPermissionRationale(() -> Unit)`，传入一个 lambda，该 lambda 将通过调用`requestLocationPermission()`来请求位置权限。否则，它将直接通过调用`requestLocationPermission()`函数来请求位置权限。

1.  确定您的应用程序是否已经具有位置权限，请在`requestPermissionWithRationaleIfNeeded()`函数之前引入此处所示的`hasLocationPermission()`函数：

```kt
private fun hasLocationPermission() =
    ContextCompat.checkSelfPermission(
        this, Manifest.permission.ACCESS_FINE_LOCATION
    ) == PackageManager.PERMISSION_GRANTED
```

1.  最后，更新`MapsActivity`类的`onMapReady()`函数，以在地图准备就绪时请求权限或获取用户的当前位置：

```kt
override fun onMapReady(googleMap: GoogleMap) {
    mMap = googleMap
    if (hasLocationPermission()) {
        getLastLocation()
    } else {
        requestPermissionWithRationaleIfNeeded()
    }
}
```

1.  为了确保在用户拒绝权限时呈现理由，更新`onRequestPermissionsResult(Int, Array<String>, IntArray)`，加入一个`else`条件：

```kt
override fun onRequestPermissionsResult(
    requestCode: Int,
    permissions: Array<out String>,
    grantResults: IntArray
) {
    super.onRequestPermissionsResult(requestCode, permissions, 
      grantResults)
    when (requestCode) {
        PERMISSION_CODE_REQUEST_LOCATION -> if (
            grantResults[0] == PackageManager.PERMISSION_GRANTED
        ) {
            getLastLocation()
        } else {
            requestPermissionWithRationaleIfNeeded()
        }
    }
}
```

1.  运行您的应用程序。现在，您应该看到一个系统权限对话框，请求您允许应用程序访问设备的位置：

![图 7.7：应用程序请求位置权限](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_07.jpg)

图 7.7：应用程序请求位置权限

如果您拒绝权限，将出现理由对话框，然后是另一个系统权限对话框，请求权限，如下截图所示。这次，用户可以选择不让应用程序再次请求权限。每当用户选择拒绝权限时，理由对话框将再次呈现给他们，直到他们选择允许权限或选中`不再询问`选项：

![图 7.8：不再询问](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_08.jpg)

图 7.8：不再询问

一旦用户允许或永久拒绝权限，对话框将不会再次显示。要重置应用程序权限的状态，您必须通过`应用信息`界面手动授予该权限。

现在我们可以获取位置权限，接下来我们将查看如何获取用户的当前位置。

# 显示用户位置的地图

成功获得用户访问其位置的权限后，我们现在可以要求用户的设备提供其上次已知的位置，这通常也是用户的当前位置。然后，我们将使用此位置向用户呈现其当前位置的地图。

为了获取用户的上次已知位置，Google 为我们提供了 Google Play 位置服务，更具体地说是`FusedLocationProviderClient`类。`FusedLocationProviderClient`类帮助我们与 Google 的 Fused 位置提供程序 API 进行交互，这是一个智能地结合来自多个设备传感器的不同信号以向我们提供设备位置信息的位置 API。

要访问`FusedLocationProviderClient`类，我们必须首先在项目中包含 Google Play 位置服务库。这意味着将以下代码片段添加到应用程序`build.gradle`的`dependencies`块中：

```kt
implementation "com.google.android.gms:play-services-location:17.1.0"
```

导入位置服务后，我们现在可以通过调用`LocationServices.getFusedLocationProviderClient(this@MainActivity)`来获取`FusedLocationProviderClient`类的实例。

一旦我们有了融合位置客户端，并且已经从用户那里获得了位置权限，我们可以通过调用`fusedLocationClient.lastLocation`来获取用户的最后位置。由于这是一个异步调用，我们至少应该提供一个成功的监听器。如果需要的话，我们还可以添加取消、失败和请求完成的监听器。`getLastLocation()`调用（在 Kotlin 中为`lastLocation`）返回一个`Task<Location>`。Task 是一个 Google API 的抽象类，其实现执行异步操作。在这种情况下，该操作是返回一个位置。因此，添加监听器只是简单地进行链接。我们将在我们的调用中添加以下代码片段：

```kt
.addOnSuccessListener { location: Location? ->
}
```

请注意，如果客户端未能获取用户的当前位置，则`location`参数可能为`null`。这并不常见，但如果例如用户在通话期间禁用了其位置服务，这种情况可能发生。

一旦我们成功监听器块内的代码被执行并且`location`不为 null，我们就可以得到用户当前位置的`Location`实例。

`Location`实例保存地球上的单个坐标，使用经度和纬度表示。对于我们的目的，知道地球表面上的每个点都映射到一对经度（缩写：Lng）和纬度（缩写：Lat）值就足够了。

这就是真正令人兴奋的地方。谷歌让我们可以使用`SupportMapFragment`类在交互式地图上呈现任何位置。只需注册一个免费的 API 密钥。当您使用 Google Maps Activity 创建应用程序时，Google 会为我们生成一个额外的文件，名为`google_maps_api.xml`，可以在`res/values`下找到。该文件对于我们的`SupportMapFragment`类是必需的，因为它包含我们的 API 密钥。它还包含如何获取新 API 密钥的清晰说明。方便的是，它还包含一个链接，该链接将为我们填写大部分所需的注册数据。链接看起来类似于`https://console.developers.google.com/flows/enableapi?apiid=...`。从`google_maps_api.xml`文件中复制它到您的浏览器（或在链接上*CMD* + *click*），一旦页面加载，按照页面上的说明操作，然后点击`Create`。一旦您获得了密钥，用您新获得的密钥替换文件底部的`YOUR_KEY_HERE`字符串。

此时，如果您运行您的应用程序，您将在屏幕上看到一个交互式地图：

![图 7.9：交互式地图](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_09.jpg)

图 7.9：交互式地图

为了根据我们的当前位置定位地图，我们使用来自我们的`Location`实例的坐标创建一个`LatLng`实例，并在`GoogleMap`实例上调用`moveCamera(CameraUpdate)`。为满足`CameraUpdate`的要求，我们调用`CameraUpdateFactory.newLatLng(LatLng)`，传入之前创建的`LatLng`参数。调用看起来会像这样：

```kt
mMap.moveCamera(CameraUpdateFactory.newLatLng(latLng))
```

我们还可以调用`newLatLngZoom(LatLng, Float)`来修改地图的放大和缩小功能。

注意

有效的缩放值范围在`2.0`（最远）和`21.0`（最近）之间。超出该范围的值将被限制。

某些区域可能没有瓦片来渲染最接近的缩放值。要了解其他可用的`CameraUpdateFactory`选项，请访问[`developers.google.com/android/reference/com/google/android/gms/maps/CameraUpdateFactory.html`](https://developers.google.com/android/reference/com/google/android/gms/maps/CameraUpdateFactory.html)。

要在用户的坐标处添加一个标记（在 Google 的地图 API 中称为标记），我们在`GoogleMap`实例上调用`addMarker(MarkerOptions)`。`MarkerOptions`参数通过链接到`MarkerOptions()`实例的调用进行配置。对于我们所需位置的简单标记，我们可以调用`position(LatLng)`和`title(String)`。调用看起来类似于以下内容：

```kt
mMap.addMarker(MarkerOptions().position(latLng).title("Pin Label"))
```

我们链接调用的顺序并不重要。

让我们在以下练习中练习一下。

## 练习 7.02：获取用户的当前位置

现在，您的应用程序可以被授予位置权限，您可以继续利用位置权限来获取用户的当前位置。然后，您将显示地图并更新地图以放大到用户的当前位置并在该位置显示一个图钉。执行以下步骤：

1.  首先，将 Google Play 位置服务添加到您的`build.gradle`文件中。您应该在`dependencies`块内添加它：

```kt
dependencies {
    implementation "com.google.android.gms:play-services-      location:17.1.0"
    implementation "org.jetbrains.kotlin:kotlin-      stdlib:$kotlin_version"
    implementation 'androidx.core:core-ktx:1.3.2'
    implementation 'androidx.appcompat:appcompat:1.2.0'
    implementation 'com.google.android.material:material:1.2.1'
    implementation 'com.google.android.gms:play-services-maps:17.0.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.0.4'
    testImplementation 'junit:junit:4.+'
    androidTestImplementation 'androidx.test.ext:junit:1.1.2'
    androidTestImplementation 'androidx.test       .espresso:espresso-core:3.3.0'
}
```

1.  单击 Android Studio 中的`Sync Project with Gradle Files`按钮，以便 Gradle 获取新添加的依赖项。

1.  获取 API 密钥：首先打开生成的`google_maps_api.xml`文件（`app/src/debug/res/values/google_maps_api.xml`），然后*CMD* + *点击*以开始的链接，该链接以`https://console.developers.google.com/flows/enableapi?apiid=`开头。

1.  按照网站上的说明操作，直到生成一个新的 API 密钥。

1.  通过将以下行中的`YOUR_KEY_HERE`替换为您的新 API 密钥来更新您的`google_maps_api.xml`文件：

```kt
<string name="google_maps_key" templateMergeStrategy="preserve"   translatable="false">YOUR_KEY_HERE</string>
```

1.  打开您的`MapsActivity.kt`文件。在您的`MapsActivity`类的顶部，定义一个延迟初始化的融合位置提供程序客户端：

```kt
class MapsActivity : AppCompatActivity(), OnMapReadyCallback {
    fusedLocationProviderClient initialize lazily, you are making sure it is only initialized when needed, which essentially guarantees the Activity class will have been created before initialization.
```

1.  在`getLastLocation()`函数之后立即引入一个`updateMapLocation(LatLng)`函数和一个`addMarkerAtLocation(LatLng, String)`函数，以在给定位置放大地图并在该位置添加一个标记：

```kt
private fun updateMapLocation(location: LatLng) {
    mMap.moveCamera(CameraUpdateFactory.newLatLngZoom(location, 7f))
}
private fun addMarkerAtLocation(location: LatLng, title: String) {
    mMap.addMarker(MarkerOptions().title(title).position(location))
}
```

1.  现在更新您的`getLastLocation()`函数以检索用户的位置：

```kt
private fun getLastLocation() {
    fusedLocationProviderClient.lastLocation
        .addOnSuccessListener { location: Location? ->
            location?.let {
                val userLocation = LatLng(location.latitude,                   location.longitude)
                updateMapLocation(userLocation)
                addMarkerAtLocation(userLocation, "You")
            }
        }
}
```

您的代码通过调用`lastLocation`以 Kotlin 简洁的方式请求最后的位置，然后将`lambda`函数附加为`OnSuccessListener`接口。一旦获得位置，`lambda`函数将被执行，更新地图位置并在该位置添加一个标题为`You`的标记（如果返回的位置不为空）。

1.  运行您的应用程序：

![图 7.10：带有当前位置标记的交互式地图](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_10.jpg)

图 7.10：带有当前位置标记的交互式地图

一旦应用程序获得了权限，它可以通过融合位置提供程序客户端从 Google Play 位置服务获取用户的最后位置。这为您提供了一种轻松简洁的方式来获取用户的当前位置。请记住在设备上打开位置以使应用程序正常工作。

有了用户的位置，您的应用程序可以告诉地图在哪里放大并在哪里放置一个图钉。如果用户点击图钉，他们将看到您分配给它的标题（在练习中为`You`）。

在下一节中，我们将学习如何响应地图上的点击事件以及如何移动标记。

# 地图点击和自定义标记

通过在正确的位置放大并放置一个图钉来显示用户当前位置的地图，我们已经初步了解了如何渲染所需的地图，以及如何获取所需的权限和用户当前位置。

在本节中，我们将学习如何响应用户与地图的交互，以及如何更广泛地使用标记。我们将学习如何在地图上移动标记以及如何用自定义图标替换默认的图钉。当我们知道如何让用户在地图上任何地方放置一个标记时，我们可以让他们选择在哪里部署秘密猫特工。

监听地图上的点击事件，我们需要向`GoogleMap`实例添加一个监听器。查看我们的`MapsActivity.kt`文件，最好的地方是在`onMapReady(GoogleMap)`中这样做。一个天真的实现看起来像这样：

```kt
override fun onMapReady(googleMap: GoogleMap) {
    mMap = googleMap.apply {
        setOnMapClickListener { latLng ->
            addMarkerAtLocation(latLng, "Deploy here")
        }
    }
    ...
}
```

但是，如果我们运行此代码，我们会发现对地图上的每次点击都会添加一个新的标记。这不是我们期望的行为。

要控制地图上的标记，我们需要保留对该标记的引用。这可以通过保留对`GoogleMap.addMarker(MarkerOptions)`的输出的引用来轻松实现。`addMarker`函数返回一个`Marker`实例。要在地图上移动标记，我们只需通过调用其`position`设置器为其分配一个新值。

要用自定义图标替换默认的标记图标，我们需要为标记或`MarkerOptions()`实例提供`BitmapDescriptor`。`BitmapDescriptor`包装器可以解决`GoogleMap`用于渲染标记（和地面覆盖，但我们不会在本书中涵盖）的位图。我们通过使用`BitmapDescriptorFactory`来获取`BitmapDescriptor`。工厂将需要一个资产，可以通过多种方式提供。您可以使用`assets`目录中位图的名称、`Bitmap`、内部存储中文件的文件名或资源 ID 来提供它。工厂还可以创建不同颜色的默认标记。我们对`Bitmap`选项感兴趣，因为我们打算使用矢量可绘制，而这些不是工厂直接支持的。此外，当将可绘制对象转换为`Bitmap`时，我们可以对其进行操作以满足我们的需求（例如，我们可以更改其颜色）。

Android Studio 为我们提供了相当广泛的免费矢量`Drawables`。在这个例子中，我们想要`paw`可绘制。为此，右键单击左侧 Android 窗格中的任何位置，然后选择`New` | `Vector Asset`。

现在，点击`Clip Art`标签旁边的 Android 图标，查看图标列表：

![图 7.11：资产工作室](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_11.jpg)

图 7.11：资产工作室

现在我们将访问一个窗口，我们可以从提供的剪贴画池中选择：

![图 7.12：选择图标](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_12.jpg)

图 7.12：选择图标

一旦我们选择了一个图标，我们可以给它命名，它将作为一个矢量可绘制的 XML 文件为我们创建。我们将它命名为`target_icon`。

要使用创建的资产，我们必须首先将其作为`Drawable`实例获取。这是通过调用`ContextCompat.getDrawable(Context, Int)`来实现的，传入活动和`R.drawable.target_icon`作为对我们资产的引用。接下来，我们需要为`Drawable`实例定义绘制的边界。调用`Drawable.setBound(Int, Int, Int, Int)`，参数为(`0`, `0`, `drawable.intrinsicWidth`, `drawable.intrinsicHeight`)，告诉它在其固有大小内绘制。

要更改图标的颜色，我们必须对其进行着色。要以一种受到早于`21`的 API 运行的设备支持的方式对`Drawable`实例进行着色，我们必须首先通过调用`DrawableCompat.wrap(Drawable)`将我们的`Drawable`实例包装在`DrawableCompat`中。然后可以使用`DrawableCompat.setTint(Drawable, Int)`对返回的`Drawable`进行着色。

接下来，我们需要创建一个`Bitmap`来容纳我们的图标。它的尺寸可以与`Drawable`的边界匹配，我们希望它的`Config`是`Bitmap.Config.ARGB_8888` - 这意味着完整的红色、绿色、蓝色和 alpha 通道。然后我们为`Bitmap`创建一个`Canvas`，允许我们通过调用`Drawable.draw(Canvas)`来绘制我们的`Drawable`实例：

```kt
private fun getBitmapDescriptorFromVector(@DrawableRes   vectorDrawableResourceId: Int): BitmapDescriptor? {
    val bitmap =
        ContextCompat.getDrawable(this, vectorDrawableResourceId)?.let {           vectorDrawable ->
            vectorDrawable
                .setBounds(0, 0, vectorDrawable.intrinsicWidth,                   vectorDrawable.intrinsicHeight)
            val drawableWithTint = DrawableCompat.wrap(vectorDrawable)
            DrawableCompat.setTint(drawableWithTint, Color.RED)
            val bitmap = Bitmap.createBitmap(
                vectorDrawable.intrinsicWidth,
                vectorDrawable.intrinsicHeight,
                Bitmap.Config.ARGB_8888
            )
            val canvas = Canvas(bitmap)
            drawableWithTint.draw(canvas)
            bitmap
        }
    return BitmapDescriptorFactory.fromBitmap(bitmap)      .also {
          bitmap?.recycle()
    }
}
```

有了包含我们图标的`Bitmap`，我们现在可以从`BitmapDescriptorFactory`中获取一个`BitmapDescriptor`实例。不要忘记在之后回收您的`Bitmap`。这将避免内存泄漏。

您已经学会了如何通过将地图居中在用户的当前位置并使用标记标记显示他们的当前位置来向用户呈现有意义的地图。

## 练习 7.03：在地图被点击的地方添加自定义标记

在这个练习中，您将通过在地图上的用户点击位置放置一个红色的爪形标记来响应用户的地图点击：

1.  在`MapsActivity.kt`（位于`app/src/main/java/com/example/catagentdeployer`下），在`mMap`变量的定义下面，定义一个可空的`Marker`变量，用于在地图上保存爪标记的引用：

```kt
private lateinit var mMap: GoogleMap
private var marker: Marker? = null
```

1.  更新`addMarkerAtLocation(LatLng, String)`，也接受一个可空的`BitmapDescriptor`，默认值为`null`：

```kt
private fun addMarkerAtLocation(
    location: LatLng,
    title: StringmarkerIcon provided is not null, the app sets it to MarkerOptions. The function now returns the marker it added to the map.
```

1.  在您的`addMarkerAtLocation(LatLng, String, BitmapDescriptor?): Marker`函数下面创建一个`getBitmapDescriptorFromVector(Int): BitmapDescriptor?`函数，以提供给定`Drawable`资源 ID 的`BitmapDescriptor`：

```kt
private fun getBitmapDescriptorFromVector(@DrawableRes   vectorDrawableResourceId: Int): BitmapDescriptor? {
    val bitmap =
        ContextCompat.getDrawable(this,           vectorDrawableResourceId)?.let { vectorDrawable ->
            vectorDrawable
                .setBounds(0, 0, vectorDrawable.intrinsicWidth,                   vectorDrawable.intrinsicHeight)
            val drawableWithTint = DrawableCompat               .wrap(vectorDrawable)
            DrawableCompat.setTint(drawableWithTint, Color.RED)
            val bitmap = Bitmap.createBitmap(
                vectorDrawable.intrinsicWidth,
                vectorDrawable.intrinsicHeight,
                Bitmap.Config.ARGB_8888
            )
            val canvas = Canvas(bitmap)
            drawableWithTint.draw(canvas)
            bitmap
        }
    return BitmapDescriptorFactory.fromBitmap(bitmap).also {
        bitmap?.recycle()
    }
}
```

此函数首先使用`ContextCompat`获取可绘制对象，通过传入提供的资源 ID。然后为可绘制对象设置绘制边界，将其包装在`DrawableCompat`中，并将其色调设置为红色。

然后，它为该`Bitmap`创建了一个`Canvas`，在其上绘制了着色的可绘制对象。然后将位图返回以供`BitmapDescriptorFactory`使用以构建`BitmapDescriptor`。最后，为了避免内存泄漏，回收`Bitmap`。

1.  在您可以使用`Drawable`实例之前，您必须首先创建它。右键单击 Android 窗格，然后选择`New` | `Vector Asset`。

1.  在打开的窗口中，单击“剪贴画”标签旁边的 Android 图标，以选择不同的图标：![图 7.13：资源工作室](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_13.jpg)

图 7.13：资源工作室

1.  从图标列表中，选择`pets`图标。如果找不到图标，可以在搜索框中输入`pets`。选择`pets`图标后，单击“确定”：![图 7.14：选择图标](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_14.jpg)

图 7.14：选择图标

1.  将您的图标命名为`target_icon`。单击“下一步”和“完成”。

1.  定义一个`addOrMoveSelectedPositionMarker(LatLng)`函数来创建一个新的标记，或者如果已经创建了一个标记，则将其移动到提供的位置。在`getBitmapDescriptorFromVector(Int)`函数之后添加它：

```kt
private fun addOrMoveSelectedPositionMarker(latLng: LatLng) {
    if (marker == null) {
        marker = addMarkerAtLocation(
            latLng, "Deploy here",               getBitmapDescriptorFromVector(R.drawable.target_icon)
        )
    } else {
        marker?.apply {
            position = latLng
        }
    }
}
```

1.  更新您的`onMapReady(GoogleMap)`函数，为`mMap`设置一个`OnMapClickListener`事件，该事件将在点击的位置添加一个标记，或将现有标记移动到点击的位置：

```kt
override fun onMapReady(googleMap: GoogleMap) {
    mMap = googleMap.apply {
        setOnMapClickListener { latLng ->
            addOrMoveSelectedPositionMarker(latLng)
        }
    }
    if (hasLocationPermission()) {
        getLastLocation()
    } else {
        requestPermissionWithRationaleIfNeeded()
    }
}
```

1.  运行您的应用程序：![图 7.15：完整的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_07_15.jpg)

图 7.15：完整的应用程序

现在，单击地图上的任何位置将会将爪印图标移动到该位置。单击爪印图标将显示“部署在这里”标签。请注意，爪印的位置是地理位置，而不是屏幕位置。这意味着如果您拖动地图或放大地图，爪印将随地图移动并保持在相同的地理位置。您现在知道如何响应用户在地图上的点击，以及如何添加和移动标记。您还知道如何自定义标记的外观。

## 活动 7.01：创建一个查找停放汽车位置的应用程序

有些人经常忘记他们停放汽车的地方。假设您想通过开发一个应用程序来帮助这些人，让用户存储他们上次停放的地方。当用户启动应用程序时，它将显示一个在用户告诉应用程序汽车位置的最后一个地方的标记。用户可以单击“我停在这里”按钮，以便在下次停放时将标记位置更新为当前位置。

您在此活动中的目标是开发一个应用程序，向用户显示带有当前位置的地图。它首先必须要求用户允许访问其位置。根据 SDK，确保在需要时还提供合理的对话框。该应用程序将在用户上次告诉它汽车位置的地方显示汽车图标。用户可以单击标有“我停在这里”的按钮，将汽车图标移动到当前位置。当用户重新启动应用程序时，它将显示用户的当前位置和汽车上次停放的位置。

作为应用程序的额外功能，您可以选择添加存储汽车位置的功能，以便在用户关闭然后重新打开应用程序后可以恢复该位置。此额外功能依赖于使用`SharedPreferences`；这是*第十一章*“持久化数据”中将介绍的一个概念。因此，下面的第 9 和第 10 步将为您提供所需的实现。

以下步骤将帮助您完成此活动：

1.  创建一个 Google Maps Activity 应用程序。

1.  获取应用程序的 API 密钥，并使用该密钥更新您的`google_maps_api.xml`文件。

1.  在底部显示一个标有“我停在这里”的按钮。

1.  在您的应用程序中包含位置服务。

1.  请求用户的位置访问权限。

1.  获取用户的位置并在地图上放置一个标记。

1.  将汽车图标添加到您的项目中。

1.  为汽车图标添加功能，将其移动到用户当前位置。

1.  将选定的位置存储在`SharedPreferences`中。放置在您的活动中的此函数将有所帮助：

```kt
private fun saveLocation(latLng: LatLng) =
    getPreferences(MODE_PRIVATE)?.edit()?.apply {
        putString("latitude", latLng.latitude.toString())
        putString("longitude", latLng.longitude.toString())
        apply()
    }
```

1.  从`SharedPreferences`中恢复任何保存的位置。您可以使用以下函数：

```kt
    val latitude = sharedPreferences.getString("latitude", null)      ?.toDoubleOrNull() ?: return null
    val longitude = sharedPreferences.getString("longitude",       null)?.toDoubleOrNull()       ?: return null
```

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 摘要

在本章中，我们学习了关于 Android 权限的知识。我们谈到了拥有这些权限的原因，并看到了如何请求用户的权限来执行某些任务。我们还学习了如何使用谷歌的地图 API 以及如何向用户呈现交互式地图。最后，我们利用了呈现地图和请求权限的知识，找出用户当前的位置并在地图上呈现出来。使用谷歌地图 API 还有很多可以做的事情，您可以通过某些权限探索更多可能性。现在您应该有足够的基础理解来进一步探索。要了解更多关于权限的信息，请访问 https://developer.android.com/reference/android/Manifest.permission。要了解更多关于地图 API 的信息，请访问[`developers.google.com/maps/documentation/android-sdk/intro`](https://developers.google.com/maps/documentation/android-sdk/intro)。

在下一章中，我们将学习如何使用`Services`和`WorkManager`执行后台任务。我们还将学习如何在应用程序未运行时向用户呈现通知。作为移动开发人员，拥有这些强大的工具是非常重要的。


# 第八章：服务、WorkManager 和通知

概述

本章将向您介绍在应用程序的后台管理长时间运行任务的概念。通过本章结束时，您将能够触发后台任务，为用户创建通知，当后台任务完成时启动应用程序。本章将使您对如何管理后台任务并让用户了解这些任务的进度有一个扎实的理解。

# 介绍

在上一章中，我们学习了如何从用户那里请求权限并使用谷歌的地图 API。有了这些知识，我们获得了用户的位置，并允许他们在本地地图上部署特工。在本章中，我们将学习如何跟踪长时间运行的进程，并向用户报告其进度。

我们将构建一个示例应用程序，假设**秘密猫特工**（**SCAs**）在 15 秒内部署。这样，我们就不必等待很长时间才能完成后台任务。当猫成功部署时，我们将通知用户，并让他们启动应用程序，向他们呈现成功部署的消息。

移动世界中，长时间运行的后台任务非常常见。即使应用程序不活跃，后台任务也会运行。长时间运行的后台任务的例子包括文件下载、资源清理作业、播放音乐和跟踪用户位置。在历史上，谷歌为 Android 开发者提供了多种执行此类任务的方式：服务、`JobScheduler`、Firebase 的`JobDispatcher`和`AlarmManager`。随着 Android 世界的碎片化，处理这些任务变得非常混乱。幸运的是，自 2019 年 3 月以来，我们有了更好（更稳定）的选择。随着`WorkManager`的推出，谷歌已经为我们抽象出了根据 API 版本选择后台执行机制的逻辑。我们仍然使用前台服务，这是一种特殊类型的服务，用于在运行中的应用程序中应用用户应该知道的某些任务，比如播放音乐或跟踪用户的位置。

在我们继续之前，先快速回顾一下。我们已经提到了服务，我们将专注于前台服务，但我们还没有完全解释服务是什么。服务是设计为在后台运行的应用程序组件，即使应用程序不运行。除了与通知相关联的前台服务外，服务没有用户界面。重要的是要注意，服务在其托管进程的主线程上运行。这意味着它们的操作可能会阻塞应用程序。我们需要在服务内部启动一个单独的线程来避免这种情况。

让我们开始看一下 Android 中管理后台任务的多种方法的实现。

# 使用 WorkManager 启动后台任务

我们将在这里首先要解决的问题是，我们应该选择`WorkManager`还是前台服务？要回答这个问题，一个很好的经验法则是问：您是否需要用户实时跟踪操作？如果答案是肯定的（例如，如果您有任务，如响应用户位置或在后台播放音乐），那么您应该使用前台服务，并附加通知以向用户实时指示状态。当后台任务可以延迟或不需要用户交互时（例如，下载大文件），请使用`WorkManager`。

注意

从`WorkManager`的 2.3.0-alpha02 版本开始，您可以通过调用`setForegroundAsync(ForegroundInfo)`来启动前台服务。我们对前台服务的控制相当有限。它确实允许您将（预定义的）通知附加到工作中，这就是值得一提的原因。

在我们的例子中，在我们的应用程序中，我们将跟踪 SCA 的部署准备。在特工出发之前，他们需要伸展、梳理毛发、去猫砂盆和穿上衣服。每一个任务都需要一些时间。因为你不能催促一只猫，特工将在自己的时间内完成每一步。我们能做的就是等待（并在任务完成时通知用户）。`WorkManager`对于这样的情况非常合适。

要使用`WorkManager`，我们需要熟悉它的四个主要类：

+   第一个是`WorkManager`本身。`WorkManager`接收工作并根据提供的参数和约束（如互联网连接和设备充电）对其进行排队。

+   第二个是`Worker`。现在，`Worker`是需要执行的工作的包装器。它有一个函数`doWork()`，我们重写它来实现后台工作代码。`doWork()`将在后台线程中执行。

+   第三个类是`WorkRequest`。这个类将`Worker`类与参数和约束绑定在一起。有两种类型的`WorkRequest`：`OneTimeWorkRequest`，它运行一次工作，和`PeriodicWorkRequest`，它可以用来安排工作以固定间隔运行。

+   第四个类是`ListenableWorker.Result`。你可能已经猜到了，但这是保存执行工作结果的类。结果可以是`Success`、`Failure`或`Retry`中的一个。

除了这四个类，我们还有`Data`类，它保存了传递给工作者和从工作者传递出来的数据。

让我们回到我们的例子。我们想定义四个需要按顺序发生的任务：猫需要伸展，然后它需要梳理毛发，然后去猫砂盆，最后，它需要穿上衣服。

在我们开始使用`WorkManager`之前，我们必须首先在我们的应用程序`build.gradle`文件中包含其依赖项：

```kt
implementation "androidx.work:work-runtime:2.4.0"
```

有了`WorkManager`包含在我们的项目中，我们将继续创建我们的工作者。第一个工作者将如下所示：

```kt
class CatStretchingWorker(
    context: Context,
    workerParameters: WorkerParameters
) : Worker(context, workerParameters) {
    override fun doWork(): Result {
        val catAgentId = inputData.getString(INPUT_DATA_CAT_AGENT_ID)
        Thread.sleep(3000L)
        val outputData = Data.Builder()
            .putString(OUTPUT_DATA_CAT_AGENT_ID, catAgentId)
            .build()
        return Result.success(outputData)
    }
    companion object {
        const val INPUT_DATA_CAT_AGENT_ID = "id"
        const val OUTPUT_DATA_CAT_AGENT_ID = "id"
    }
}
```

我们首先通过扩展`Worker`并重写其`doWork()`函数来开始。然后，我们从输入数据中读取 SCA ID。然后，因为我们没有真正的传感器来跟踪猫伸展的进度，我们通过引入一个 3 秒（3,000 毫秒）的`Thread.sleep(Long)`调用来伪造等待。最后，我们用我们在输入中收到的 ID 构造一个输出数据类，并将其与成功的结果一起返回。

一旦我们为所有任务创建了工作者（`CatStretchingWorker`、`CatFurGroomingWorker`、`CatLitterBoxSittingWorker`和`CatSuitUpWorker`），类似于我们创建第一个工作者的方式，我们可以调用`WorkManager`来将它们链接起来。假设我们无法在没有连接到互联网时了解特工的进度。我们的调用将如下所示：

```kt
val catStretchingInputData = Data.Builder()
  .putString(CatStretchingWorker.INPUT_DATA_CAT_AGENT_ID, 
    "catAgentId").build()
val catStretchingRequest = OneTimeWorkRequest
  .Builder(CatStretchingWorker::class.java)
val catStretchingRequest =   OneTimeWorkRequest.Builder(CatStretchingWorker::class.java)
    .setConstraints(networkConstraints)
    .setInputData(catStretchingInputData)
    .build()
...
WorkManager.getInstance(this).beginWith(catStretchingRequest)
    .then(catFurGroomingRequest)
    .then(catLitterBoxSittingRequest)
    .then(catSuitUpRequest)
    .enqueue()
```

在上述代码中，我们首先构造了一个`Constraints`实例，声明我们需要连接到互联网才能执行工作。然后，我们定义了我们的输入数据，将其设置为 SCA ID。接下来，我们通过构造`OneTimeWorkRequest`将约束和输入数据绑定到我们的`Worker`类。其他`WorkRequest`实例的构造已经被省略了，但它们与这里显示的基本相同。现在我们可以将所有请求链接起来并将它们排队到`WorkManager`类上。您可以通过直接将单个`WorkRequest`实例传递给`WorkManager`的`enqueue()`函数来排队一个单独的`WorkRequest`实例，或者您也可以通过将它们全部传递给`WorkManager`的`enqueue()`函数作为列表来并行运行多个`WorkRequest`实例。

当满足约束时，我们的任务将由`WorkManager`执行。

每个`Request`实例都有一个唯一的标识符。`WorkManager`为每个请求公开了一个`LiveData`属性，允许我们通过传递其唯一标识符来跟踪其工作的进度，如下面的代码所示：

```kt
workManager.getWorkInfoByIdLiveData(catStretchingRequest.id)
    .observe(this, Observer { info ->
        if (info.state.isFinished) {
            doSomething()
        }
    })
```

最后，还有 `Result.retry`。返回此结果会告诉 `WorkManager` 类重新排队工作。决定何时再次运行工作的策略由设置在 `WorkRequest` `Builder` 上的 `backoff` 标准定义。默认的 `backoff` 策略是指数的，但我们也可以将其设置为线性的。我们还可以定义初始的 `backoff` 时间。

这将为 `Worker` 实现添加所需的依赖项，然后扩展 `Worker` 类。要实现实际的工作，你将重写 `doWork(): Result`，使其从输入中读取 Cat Agent ID，休眠 `3` 秒（`3000` 毫秒），使用 Cat Agent ID 构造一个输出数据实例，并将其传递到 `Result.success` 值中。

在这个第一个练习中，我们将跟踪 SCA 在准备出发时通过排队的链式 `WorkRequest` 类：

在这一部分，我们将从我们发出部署到现场的命令开始跟踪我们的 SCA，直到它到达目的地。

## 要定义一个将休眠 `3` 秒的 `Worker` 实例，更新新类如下：

练习 8.01：使用 WorkManager 类执行后台工作

1.  首先创建一个新的 `Empty Activity` 项目（`File -> New -> New Project -> Empty Activity`）。点击 `Next`。

1.  让我们在接下来的练习中实践到目前为止所学到的知识。

1.  确保你在 `Project` 窗格中处于 Android 视图。

1.  确保你的包名是 `com.example.catagenttracker`。

1.  将其他所有内容保持默认值，然后点击 `Finish`。

1.  将以下内容添加到 `onCreate(Bundle?)` 函数中：

1.  打开你的应用程序的 `build.gradle` 文件。在 `dependencies` 块中，添加 `WorkManager` 依赖项：

```kt
dependencies {
    implementation "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
    ...
    WorkManager and its dependencies in your code.
```

1.  工作的状态可以是 `BLOCKED`（存在一系列请求，它不是下一个请求）、`ENQUEUED`（存在一系列请求，这项工作是下一个请求）、`RUNNING`（`doWork()` 中的工作正在执行）和 `SUCCEEDED`。工作也可以被取消，导致 `CANCELLED` 状态，或者失败，导致 `FAILED` 状态。

1.  用户可见的后台操作 - 使用前台服务

1.  在 `com.example.catagenttracker.worker` 下创建一个名为 `CatStretchingWorker` 的新类（右键单击 `worker`，然后选择 `New` | `New Kotlin File/Class`）。在 `Kind` 下，选择 `Class`。

```kt
package com.example.catagenttracker.worker
import android.content.Context
import androidx.work.Data
import androidx.work.Worker
import androidx.work.WorkerParameters
class CatStretchingWorker(
    context: Context,
    workerParameters: WorkerParameters
) : Worker(context, workerParameters) {
    override fun doWork(): Result {
        val catAgentId = inputData.getString(INPUT_DATA_CAT_AGENT_ID)
        Thread.sleep(3000L)
        val outputData = Data.Builder()
            .putString(OUTPUT_DATA_CAT_AGENT_ID, catAgentId)
            .build()
        return Result.success(outputData)
    }
    companion object {
        const val INPUT_DATA_CAT_AGENT_ID = "inId"
        const val OUTPUT_DATA_CAT_AGENT_ID = "outId"
    }
}
```

将你的应用程序命名为 `Cat Agent Tracker`。

1.  运行你的应用程序：

1.  打开 `MainActivity`。在类的末尾之前，添加以下内容：

```kt
private fun getCatAgentIdInputData(catAgentIdKey: String,   catAgentIdValue: String) =
    Data.Builder().putString(catAgentIdKey, catAgentIdValue)
        .build()
```

这个辅助函数为你构造了一个带有 Cat Agent ID 的输入 `Data` 实例。

1.  将以下内容按行翻译成中文：

```kt
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    WorkManager class to wait for an internet connection before executing work. Then, you define your Cat Agent ID. Finally, you define four requests, passing in your Worker classes, the network constraints, and the Cat Agent ID in the form of input data.
```

1.  将保存位置设置为你想要保存项目的位置。

```kt
private val workManager = WorkManager.getInstance(this)
```

1.  在你的应用程序包下创建一个新的包（右键单击 `com.example.catagenttracker`，然后选择 `New` | `Package`）。将新包命名为 `com.example.catagenttracker.worker`。

```kt
val catSuitUpRequest =   OneTimeWorkRequest.Builder(CatSuitUpWorker::class.java)
    .setConstraints(networkConstraints)
    .setInputData(
        getCatAgentIdInputData(CatSuitUpWorker           .INPUT_DATA_CAT_AGENT_ID, catAgentId)
    ).build()
WorkRequests are now enqueued to be executed in sequence when their constraints are met and the WorkManager class is ready to execute them.
```

1.  定义一个显示带有提供的消息的提示的函数。它应该看起来像这样：

```kt
private fun showResult(message: String) {
    Toast.makeText(this, message, LENGTH_SHORT).show()
}
```

1.  为了跟踪排队的 `WorkRequest` 实例的进度，在 `enqueue` 调用之后添加以下内容：

```kt
workManager.beginWith(catStretchingRequest)
    .then(catFurGroomingRequest)
    .then(catLitterBoxSittingRequest)
    .then(catSuitUpRequest)
    .enqueue()
WorkInfo observable provided by the WorkManager class for each WorkRequest. When each request is finished, a toast is shown with a relevant message.
```

1.  在类的顶部，定义你的 `WorkManager`：

![图 8.1：按顺序显示的提示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_08_01.jpg)

现在你应该看到一个简单的 `Hello World!` 屏幕。但是，如果你等待几秒钟，你将开始看到提示信息，告诉你 SCA 准备部署到现场的进度。你会注意到这些提示信息按照你排队请求的顺序执行它们的延迟。

图 8.1：按顺序显示的提示

在你刚刚添加的代码下方，仍然在 `onCreate` 函数内，添加一个链式的 `enqueue` 请求：# 重复步骤 9 和 10，创建三个更多相同的工作程序，分别命名为 `CatFurGroomingWorker`、`CatLitterBoxSittingWorker` 和 `CatSuitUpWorker`。我们的 SCA 已经准备好去指定的目的地了。为了跟踪 SCA，我们将使用前台服务定期轮询 SCA 的位置，并使用新位置更新附加到该服务的粘性通知（用户无法解除的通知）。为了简单起见，我们将伪造位置。根据您在*第七章*中学到的内容，*Android 权限和 Google 地图*，您可以稍后用使用地图的真实实现替换这个实现。

前台服务是执行后台操作的另一种方式。名称可能有点违反直觉。它的目的是区分这些服务与基本的 Android（后台）服务。前者与通知绑定，而后者在后台运行，没有用户界面表示。前台服务和后台服务之间的另一个重要区别是，当系统内存不足时，后者可能会被终止，而前者不会。

从 Android 9（Pie，或 API 级别 28）开始，我们必须请求`FOREGROUND_SERVICE`权限来使用前台服务。由于这是一个普通权限，它将自动授予我们的应用程序。

在我们启动前台服务之前，我们必须先创建一个。前台服务是 Android 抽象`Service`类的子类。如果我们不打算绑定到服务，而在我们的示例中确实不打算这样做，我们可以简单地重写`onBind(Intent)`，使其返回`null`。顺便说一句，绑定是感兴趣的客户端与服务通信的一种方式。在本书中，我们不会专注于这种方法，因为您将在下面发现其他更简单的方法。

前台服务必须与通知绑定。在 Android 8（Oreo 或 API 级别 26）及更高版本中，如果前台服务在服务的`onCreate()`函数中没有与通知绑定。一个快速的实现看起来会像这样：

```kt
private fun onCreate() {
    val channelId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {        
        val newChannelId = "ChannelId"
        val channelName = "My Background Service"
        val channel =
            NotificationChannel(newChannelId, channelName,               NotificationManager.IMPORTANCE_DEFAULT)
        val service = getSystemService(Context.NOTIFICATION_SERVICE) as           
            NotificationManager        
        service.createNotificationChannel(channel)       
        newChannelId    
    } else {        
        ""    
    }    
    val pendingIntent = Intent(this, MainActivity::class.java).let {       
        notificationIntent ->        
            PendingIntent.getActivity(this, 0, notificationIntent, 0)
    }    
    val notification = NotificationCompat.Builder(this, channelId)        
        .setContentTitle("Content title")
        .setContentText("Content text")
        .setSmallIcon(R.drawable.notification_icon)
        .setContentIntent(pendingIntent)
        .setTicker("Ticker message")
        .build()
    startForeground(NOTIFICATION_ID, notificationBuilder.build())
}
```

让我们来分解一下。我们首先要定义频道 ID。这仅适用于 Android Oreo 或更高版本，在早期版本的 Android 中将被忽略。在 Android Oreo 中，Google 引入了频道的概念。频道用于分组通知，并允许用户过滤掉不需要的通知：

```kt
    val channelId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {        
        val newChannelId = "ChannelId"
        val channelName = "My Background Service"        
        val channel =
            NotificationChannel(newChannelId, channelName,               NotificationManager.IMPORTANCE_DEFAULT)
        val service = getSystemService(Context.NOTIFICATION_SERVICE) as
            NotificationManager
        service.createNotificationChannel(channel)        
        newChannelId    
    } else {
        ""    
    }
```

接下来，我们定义`pendingIntent`。这将是用户点击通知时启动的意图。在这个例子中，主活动将被启动：

```kt
    val pendingIntent = Intent(this, MainActivity::class.java).let {       
        notificationIntent ->        
            PendingIntent.getActivity(this, 0, notificationIntent, 0)
    }
```

有了频道 ID 和`pendingIntent`，我们就可以构建我们的通知。我们使用`NotificationCompat`，它可以减少对支持旧 API 级别的样板代码。我们将服务作为上下文和频道 ID 传递进去。我们定义标题、文本、小图标、意图和滚动消息，并构建通知：

```kt
    val notification = NotificationCompat.Builder(this, channelId)        
        .setContentTitle("Content title")
        .setContentText("Content text") 
        .setSmallIcon(R.drawable.notification_icon)
        .setContentIntent(pendingIntent)
        .setTicker("Ticker message")
        .build()
```

要启动一个前台服务，并将通知附加到其中，我们调用`startForeground(Int, Notification)`函数，传入一个通知 ID（任何唯一的整数值来标识此服务，不能为 0）和一个通知，其优先级必须设置为`PRIORITY_LOW`或更高。在我们的情况下，我们没有指定优先级，这将使其设置为`PRIORITY_DEFAULT`：

```kt
    startForeground(NOTIFICATION_ID, notificationBuilder.build())
```

如果启动，我们的服务现在将显示一个粘性通知。点击通知将启动我们的主活动。但是，我们的服务不会执行任何有用的操作。要为其添加一些功能，我们需要重写`onStartCommand(Intent?, Int, Int)`。当服务通过意图启动时，此函数将被调用，这也给了我们机会读取通过该意图传递的任何额外数据。它还为我们提供了标志（可能设置为`START_FLAG_REDELIVERY`或`START_FLAG_RETRY`）和一个唯一的请求 ID。

我们将在本章后面读取额外的数据。在简单的实现中，您不需要担心标志或请求 ID。重要的是要注意，`onStartCommand(Intent?, Int, Int)`在 UI 线程上调用，因此不要在这里执行任何长时间运行的操作，否则您的应用程序将冻结，给用户带来不良体验。相反，我们可以使用新的`HandlerThread`（一个带有 looper 的线程，用于为线程运行消息循环的类）创建一个新的处理程序，并将我们的工作发布到其中。这意味着我们将有一个无限循环运行，等待我们通过`Handler`发布工作。当我们收到启动命令时，我们可以将要执行的工作发布到其中。然后该工作将在该线程上执行。

当我们的长时间运行的工作完成时，有一些事情可能会发生。首先，我们可能希望通知感兴趣的人（例如，如果主要活动正在运行，则通知主要活动）我们已经完成。然后，我们可能希望停止在前台运行。最后，如果我们不希望再次需要服务，我们可以停止它。

应用程序有几种与服务通信的方式——绑定、使用广播接收器、使用总线架构或使用结果接收器等。在我们的示例中，我们将使用 Google 的`LiveData`。

在我们继续之前，值得一提的是广播接收器。广播接收器允许我们的应用程序使用类似*发布-订阅设计模式*的模式发送和接收消息。

系统广播事件，例如设备启动或充电已开始。我们的服务也可以广播状态更新。例如，它们可以在完成时广播长时间的计算结果。

如果我们的应用程序注册接收某个消息，系统将在广播该消息时通知它。这曾经是与服务通信的常见方式，但`LocalBroadcastManager`类现在已被弃用，因为它是一个鼓励反模式的应用程序范围事件总线。

话虽如此，广播接收器仍然对系统范围的事件很有用。我们首先定义一个类，覆盖`BroadcastReceiver`抽象类：

```kt
class ToastBroadcastReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {        
        StringBuilder().apply {
            append("Action: ${intent.action}\n")
            append("URI: ${intent.toUri(Intent.URI_INTENT_SCHEME)}\n")
            toString().let { eventText ->
                Toast.makeText(context, eventText,
                    Toast.LENGTH_LONG).show()
            }        
        }    
    }
}
```

当`ToastBroadcastReceiver`接收到事件时，它将显示一个显示事件操作和 URI 的 toast。我们可以通过`Manifest.xml`文件注册我们的接收器：

```kt
<receiver android:name=".ToastBroadcastReceiver" android:exported="true">
    <intent-filter>        
        <action android:name=          
            "android.intent.action.ACTION_POWER_CONNECTED" />    
    </intent-filter>
</receiver>
```

指定`android:exported="true"`告诉系统此接收器可以接收来自应用程序外部的消息。操作定义了我们感兴趣的消息。我们可以指定多个操作。在此示例中，我们监听设备开始充电的情况。请记住，将此值设置为"true"允许其他应用程序，包括恶意应用程序，激活此接收器。我们也可以在代码中注册消息：

```kt
val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION).apply {    
    addAction(Intent.ACTION_POWER_CONNECTED)}
    registerReceiver(ToastBroadcastReceiver(), filter)
```

将此代码添加到活动或自定义应用程序类中将注册一个新的接收器实例。只要上下文（活动或应用程序）有效，此接收器将保持存在。因此，相应地，如果活动或应用程序被销毁，我们的接收器将被释放以进行垃圾回收。现在回到我们的实现。要在我们的应用程序中使用`LiveData`，我们必须在`app/build.gradle`文件中添加一个依赖项：

```kt
Dependencies {    
    ...    
    implementation "androidx.lifecycle:lifecycle-livedata-ktx:2.2.0"    
    ...
}
```

然后我们可以在服务的伴生对象中定义一个`LiveData`实例，如下所示：

```kt
companion object {    
    private val mutableWorkCompletion = MutableLiveData<String>()    
    val workCompletion: LiveData<String> = mutableWorkCompletion
}
```

请注意，我们将`MutableLiveData`实例隐藏在`LiveData`接口后面。这样消费者只能读取数据。现在我们可以使用`mutableWorkCompletion`实例通过为其分配一个值来报告完成。但是，我们必须记住，只能在主线程上为`LiveData`实例分配值。这意味着一旦我们的工作完成，我们必须切换回主线程。我们可以很容易地实现这一点——我们只需要一个具有主`Looper`的新处理程序（通过调用`Looper.getMainLooper()`获得），我们可以将我们的更新发布到其中。

现在我们的服务已经准备好做一些工作，我们最终可以启动它。在我们这样做之前，我们必须确保将服务添加到我们的`AndroidManifest.xml`文件中的`<application></application>`块中，如下面的代码所示：

```kt
<application ...>    
    <service android:name=".ForegroundService" />
</application>
```

要启动我们刚刚添加到清单中的服务，我们创建`Intent`，传入所需的任何额外数据，如下面的代码所示：

```kt
val serviceIntent = Intent(this, ForegroundService::class.java).apply {    
    putExtra("ExtraData", "Extra value")
}
```

然后，我们调用`ContextCompat.startForegroundService(Context, Intent)`来触发`Intent`并启动服务。

## 练习 8.02：使用前台服务跟踪您的 SCA 的工作

在第一个练习中，您使用`WorkManager`类跟踪了 SCA 在准备出发时的情况。在这个练习中，您将通过显示一个粘性通知来跟踪 SCA 在部署到现场并朝着指定目标移动的情况，倒计时到达目的地的时间。这个通知将由一个前台服务驱动，它将呈现并持续更新它。随时点击通知将启动您的主活动，如果它尚未运行，它将始终将其置于前台：

1.  通过更新应用的`build.gradle`文件，首先向您的项目添加`LiveData`依赖项：

```kt
    implementation "androidx.work:work-runtime:2.4.0"
    implementation "androidx.lifecycle:lifecycle-livedata-ktx:2.2.0"    
```

1.  然后，创建一个名为`RouteTrackingService`的新类，扩展抽象的`Service`类：

```kt
class RouteTrackingService : Service() {
    override fun onBind(intent: Intent): IBinder? = null
}
```

在这个练习中，您不会依赖绑定，因此在`onBind(Intent)`实现中简单地返回`null`是安全的。

1.  在新创建的服务中，定义一些稍后需要的常量，以及用于观察进度的`LiveData`实例：

```kt
    companion object {
        const val NOTIFICATION_ID = 0xCA7        
        const val EXTRA_SECRET_CAT_AGENT_ID = "scaId"        
        private val mutableTrackingCompletion = MutableLiveData<String>()        
        val trackingCompletion: LiveData<String> = mutableTrackingCompletion    
    }    
```

`NOTIFICATION_ID`必须是此服务拥有的通知的唯一标识符，不能是`0`。现在，`EXTRA_SECRET_CAT_AGENT_ID`是您用于向服务传递数据的常量。`mutableTrackingCompletion`是私有的，用于允许您通过`LiveData`在服务内部发布完成更新，而不会在服务外部暴露可变性。然后使用`trackingCompletion`以不可变的方式公开`LiveData`实例以供观察。

1.  在您的`RouteTrackingService`类中添加一个函数，以提供给您的粘性通知`PendingIntent`：

```kt
    private fun getPendingIntent() =        
        PendingIntent.getActivity(this, 0, Intent(this,       MainActivity::class.java), 0)    
```

这将在用户点击`Notification`时启动`MainActivity`。您调用`PendingIntent.getActivity()`，传递上下文、无请求代码（`0`）、将启动`MainActivity`的`Intent`，以及没有标志（`0`）。您会得到一个`PendingIntent`，它将启动该活动。1.  添加另一个函数来为运行 Android Oreo 或更新版本的设备创建`NotificationChannel`：

```kt
    @RequiresApi(Build.VERSION_CODES.O)    
    private fun createNotificationChannel(): String {
        val channelId = "routeTracking"
        val channelName = "Route Tracking"
        val channel =
            NotificationChannel(channelId, channelName,           
                NotificationManager.IMPORTANCE_DEFAULT)
        val service = getSystemService(Context.NOTIFICATION_SERVICE) as       
            NotificationManager        
        service.createNotificationChannel(channel)        return channelId
    }
```

首先定义频道 ID。这需要对包进行唯一标识。接下来，定义一个对用户可见的频道名称。这可以（并且应该）进行本地化。出于简单起见，我们跳过了这部分。然后创建一个`NotificationChannel`实例，将重要性设置为`IMPORTANCE_DEFAULT`。重要性决定了发布到此频道的通知有多么具有破坏性。最后，使用`Notification Service`使用`NotificationChannel`实例中提供的数据创建一个频道。该函数返回频道 ID，以便用于构造`Notification`。

1.  创建一个函数来提供`Notification.Builder`：

```kt
    private fun getNotificationBuilder(pendingIntent: PendingIntent, channelId: String) =
        NotificationCompat.Builder(this, channelId)
            .setContentTitle("Agent approaching destination")
            .setContentText("Agent dispatched")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setTicker("Agent dispatched, tracking movement")
```

此函数使用您之前创建的函数生成的`pendingIntent`和`channelId`实例，并构造一个`NotificationCompat.Builder`类。该构建器允许您定义标题（第一行）、文本（第二行）、要使用的小图标（根据设备而异的大小）、用户点击`Notification`时触发的意图以及一个提示（用于辅助功能；在 Android Lollipop 之前，这在通知被呈现之前显示）。您也可以设置其他属性。探索`NotificationCompat.Builder`类。在实际项目中，请记住使用来自 strings.xml 的字符串资源而不是硬编码的字符串。

1.  实现以下代码，引入一个函数来启动前台服务：


```kt
    private fun startForegroundService(): NotificationCompat.Builder {        
        val pendingIntent = getPendingIntent()
        val channelId =       
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {            
                createNotificationChannel()
            } else {
                ""
            }
        val notificationBuilder = getNotificationBuilder(pendingIntent,       
            channelId)
        startForeground(NOTIFICATION_ID, notificationBuilder.build())        return notificationBuilder
    }
```

您首先使用您之前引入的函数获取`PendingIntent`。然后，根据设备的 API 级别，您创建一个通知通道并获取其 ID，或者设置一个空 ID。您将`pendingIntent`和`channelId`传递给构造`NotificationCompat.Builder`的函数，并将服务作为前台服务启动，为其提供`NOTIFICATION_ID`和使用构建器构建的通知。该函数返回`NotificationCompat.Builder`，以便稍后用于更新通知。

1.  在您的服务中定义两个字段——一个用于保存可重用的`NotificationCompat.Builder`类，另一个用于保存对`Handler`的引用，稍后您将在后台中使用它来发布工作：

```kt
    private lateinit var notificationBuilder: NotificationCompat.Builder    
    private lateinit var serviceHandler: Handler    
```

1.  接下来，重写`onCreate()`以将服务作为前台服务启动，保留对`Notification.Builder`的引用，并创建`serviceHandler`：

```kt
    override fun onCreate() {
        super.onCreate()
        notificationBuilder = startForegroundService()        
        val handlerThread = HandlerThread("RouteTracking").apply {
            start()
        }
        serviceHandler = Handler(handlerThread.looper)
    }
```

请注意，要创建`Handler`实例，必须首先定义并启动`HandlerThread`。

1.  定义一个跟踪已部署的 SCA 接近其指定目的地的调用：

```kt
    private fun trackToDestination(notificationBuilder:   
        NotificationCompat.Builder) {
        for (i in 10 downTo 0) {
            Thread.sleep(1000L)
            notificationBuilder
               .setContentText("$i seconds to destination")            
            startForeground(NOTIFICATION_ID,           
                notificationBuilder.build())
        }
    }    
```

这将从`10`倒数到`1`，在更新之间每隔 1 秒休眠，然后使用剩余时间更新通知。

1.  添加一个函数，在主线程上通知观察者完成：

```kt
    private fun notifyCompletion(agentId: String) {
        Handler(Looper.getMainLooper()).post {            
            mutableTrackingCompletion.value = agentId
        }
    }    
```


通过在主`Looper`上使用处理程序发布，您确保更新发生在主（UI）应用程序线程上。当将值设置为代理 ID 时，您正在通知所有观察者该代理 ID 已到达目的地。

1.  像这样重写`onStartCommand(Intent?, Int, Int)`：

```kt
    override fun onStartCommand(intent: Intent?, flags: Int,
        startId: Int): Int {
        val returnValue = super.onStartCommand(intent, flags, startId)    
        val agentId =
            intent?.getStringExtra(EXTRA_SECRET_CAT_AGENT_ID)
            ?: throw IllegalStateException("Agent ID must be provided")
        serviceHandler.post {
            trackToDestination(notificationBuilder)            
            notifyCompletion(agentId)
            stopForeground(true)
            stopSelf()        
        }        
        return returnValue
    }    
```

您首先将调用委托给`super`，它在内部调用`onStart()`并返回一个向后兼容的状态，您可以返回。您存储此返回值。接下来，您从通过意图传递的额外参数中获取 SCA ID。如果没有提供代理 ID，则此服务将无法工作，因此如果没有提供代理 ID，您将抛出异常。接下来，您切换到在`onCreate`中定义的后台线程，以阻塞方式跟踪代理到其目的地。跟踪完成后，您通知观察者任务已完成，停止前台服务（通过传递`true`来删除通知），并停止服务本身，因为您不希望很快再次需要它。然后，您返回之前存储的`super`的返回值。

1.  更新您的`AndroidManifest.xml`以请求`FOREGROUND_SERVICE`权限并引入服务：

```kt
    <manifest ...>
```

除非我们这样做，否则系统将阻止我们的应用程序使用前台服务。接下来，我们声明服务。设置`android:enabled="true"`告诉系统它可以实例化服务。默认值为`true`，因此这是可选的。用 android 定义服务`:exported="true"`告诉系统其他应用程序可以启动该服务。在我们的例子中，我们不需要这个额外的功能，但是我们添加它只是为了让您知道这个功能。

1.  回到您的`MainActivity`。引入一个函数来启动`RouteTrackingService`：

```kt
    private fun launchTrackingService() {
        RouteTrackingService.trackingCompletion.observe(this, Observer {
            agentId -> showResult("Agent $agentId arrived!")
        })        
        val serviceIntent = Intent(this, 
            RouteTrackingService::class.java).apply {
                putExtra(EXTRA_SECRET_CAT_AGENT_ID, "007")
            }
        ContextCompat.startForegroundService(this, serviceIntent)
    }    
```


该函数首先观察`LiveData`以获取完成更新，完成时显示结果。然后，它为启动服务定义`Intent`，为该`Intent`的额外参数设置 SCA ID。然后，使用`ContextCompat`启动前台服务，该服务隐藏了与兼容性相关的逻辑。

1.  最后，更新`onCreate()`以在准备好并准备好启动时立即开始跟踪 SCA：


```kt
    workManager.getWorkInfoByIdLiveData(catSuitUpRequest.id)
        .observe(this, Observer { info ->
            if (info.state.isFinished) {
                showResult("Agent done suiting up. Ready to go!")   
                launchTrackingService()
            }
        })    
```

1.  启动应用程序：

![图 8.2：倒计时通知](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_08_02.jpg)

图 8.2：倒计时通知

在通知您 SCA 准备步骤之后，您应该在状态栏中看到一个通知。该通知然后应该从 10 倒数到 0，消失，并被一个 toast 替换，通知您代理已到达目的地。看到最后的 toast 告诉您，您成功将 SCA ID 传递给服务，并在后台任务完成时将其取回。

通过本章获得的所有知识，让我们完成以下活动。

## 活动 8.01：提醒喝水

平均每天人体失去约 2500 毫升的水（参见[`en.wikipedia.org/wiki/Fluid_balance#Output`](https://en.wikipedia.org/wiki/Fluid_balance#Output)）。为了保持健康，我们需要摄入与失去的水量相同的水。然而，由于现代生活的繁忙性质，很多人经常忘记定期补水。假设您想开发一个应用程序，跟踪您的水分流失（统计数据），并给您不断更新的液体平衡。从平衡状态开始，该应用程序将逐渐减少用户跟踪的水位。用户可以告诉应用程序他们何时喝了一杯水，它将相应地更新水位。水位的持续更新将利用您运行后台任务的知识，并且您还将利用与服务通信的知识来响应用户交互更新平衡。

以下步骤将帮助您完成此活动：

1.  创建一个空活动项目，并将您的应用命名为`My Water Tracker`。

1.  在您的`AndriodManifest.xml`文件中添加前台服务权限。

1.  创建一个新的服务。

1.  在您的服务中定义一个变量来跟踪水位。

1.  为通知 ID 和额外意图数据键定义常量。

1.  设置从服务创建通知。

1.  添加函数来启动前台服务和更新水位。

1.  将水位设置为每 5 秒减少一次。

1.  处理来自服务外部的流体添加。

1.  确保服务在销毁时清理回调和消息。

1.  在`Manifest.xml`文件中注册服务。

1.  在`MainActivity`中创建活动时启动服务。

1.  在主活动布局中添加一个按钮。

1.  当用户点击按钮时，通知服务需要增加水位。

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 摘要

在本章中，我们学习了如何使用`WorkManager`和前台服务执行长时间运行的后台任务。我们讨论了如何向用户传达进度，以及如何在任务执行完成后让用户重新进入应用程序。本章涵盖的所有主题都非常广泛，您可以进一步探索与服务通信、构建通知以及使用`WorkManager`类。希望对于大多数常见情况，您现在已经拥有所需的工具。常见用例包括后台下载、清理缓存资产、在应用程序不在前台运行时播放音乐，以及结合我们从*第七章* *Android 权限和谷歌地图*中获得的知识，随时间跟踪用户的位置。

在下一章中，我们将通过编写单元测试和集成测试来使我们的应用程序更加健壮和可维护。当您编写的代码在后台运行并且当出现问题时不会立即显现时，这将特别有帮助。


# 第九章：使用 JUnit、Mockito 和 Espresso 进行单元测试和集成测试

概述

在本章中，你将学习关于在 Android 平台上进行测试以及如何创建单元测试、集成测试和 UI 测试。你将看到如何创建这些类型的测试，分析它们的运行方式，并使用 JUnit、Mockito、Robolectric 和 Espresso 等框架进行工作。你还将学习关于测试驱动开发，这是一种将测试置于实现之上的软件开发实践。通过本章的学习，你将能够将你的新测试技能结合起来应用到一个真实项目中。

# 介绍

在之前的章节中，你学习了如何加载背景数据并在用户界面中显示它，以及如何设置 API 调用来检索数据。但是你如何确保一切正常？如果你处于一个你过去没有太多互动的项目中需要修复一个错误的情况下怎么办？你如何知道你所应用的修复不会触发另一个错误？这些问题的答案是通过测试。

在本章中，我们将分析开发人员可以编写的测试类型，并查看可用的测试工具以简化测试体验。首先出现的问题是台式机或笔记本电脑使用不同的操作系统来开发移动应用。这意味着测试也必须在设备或模拟器上运行，这将减慢测试的速度。为了解决这个问题，我们有两种类型的测试：`test`文件夹将在你的机器上运行，而`androidTest`文件夹将在设备或模拟器上运行。

这两种测试都依赖于 Java 的**JUnit**库，它帮助开发人员设置他们的测试并将它们分组到不同的类别中。它还提供了不同的配置选项，以及其他库可以构建的扩展。我们还将研究测试金字塔，它帮助指导开发人员如何组织他们的测试。我们将从金字塔的底部开始，代表着**单元测试**，向上移动通过**集成测试**，最终达到顶部，代表着**端到端测试**（UI 测试）。你将有机会学习到帮助编写每种类型测试的工具：

+   **Mockito**和**mockito-kotlin**主要帮助进行单元测试，并且对于创建模拟或测试替身非常有用，我们可以操纵输入以便断言不同的场景。（模拟或测试替身是一个模仿另一个对象实现的对象。每当一个测试与模拟对象交互时，你可以指定这些交互的行为。）

+   **Robolectric**是一个开源库，它将 Android 框架引入你的机器，允许你在本地测试活动和片段，而不是在模拟器上。这可以用于单元测试和集成测试。

+   `EditText`组件等）和断言（验证视图显示特定文本，当前显示给用户，启用等）在应用的 UI 中的仪器测试。

在本章中，我们还将介绍**测试驱动开发**（**TDD**）。这是一个测试优先的软件开发过程。简单来说，就是先编写测试。我们将分析在为 Android 应用程序开发功能时采用这种方法。要记住的一件事是，为了正确测试应用程序，其类必须正确编写。一种方法是清晰地定义类之间的边界，并根据您希望它们完成的任务对它们进行拆分。一旦您做到了这一点，您还可以在编写类时依赖于**依赖反转**和**依赖注入**原则。当这些原则得到正确应用时，您应该能够将虚假对象注入到测试对象中，并操纵输入以适应您的测试场景。依赖注入还有助于编写插装测试，以帮助您用本地数据替换进行网络调用的模块，以使您的测试独立于网络等外部因素。插装测试是在设备或模拟器上运行的测试。 "插装"关键字来自插装框架，该框架组装这些测试，然后在设备上执行它们。

理想情况下，每个应用程序应该有三种类型的测试：

+   **单元测试**：这些是验证单个类和方法的本地测试。它们应该占大多数测试，并且它们应该快速、易于调试和易于维护。它们也被称为小型测试。

+   **集成测试**：这些是使用 Robolectric 的本地测试，或验证应用程序模块和组件之间交互的插装测试。这些比单元测试更慢，更复杂。复杂性的增加是由于组件之间的交互。这些也被称为中型测试。

+   **UI 测试（端到端测试）**：这些是验证完整用户旅程和场景的插装测试。这使它们更复杂，更难以维护；它们应该代表您总测试数量中的最少部分。这些也被称为大型测试。

在下图中，您可以观察到**测试金字塔**。Google 的建议是保持 70:20:10（单元测试：集成测试：UI 测试）的比例：

![图 9.1：测试金字塔](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_01.jpg)

图 9.1：测试金字塔

如前一节所述，单元测试是验证代码的一小部分的测试，大多数测试应该是覆盖各种场景（成功、错误、限制等）的单元测试。理想情况下，这些测试应该是本地的，但也有一些例外情况，您可以将它们制作成插装测试。这些情况很少，应该限制在您想要与设备的特定硬件交互时。

# JUnit

JUnit 是一个用于在 Java 和 Android 中编写单元测试的框架。它负责测试的执行方式，允许开发人员配置他们的测试。它提供了许多功能，例如以下内容：

+   `@Before`和`@After`注解。

+   **断言**：用于验证操作的结果与预期值是否一致。

+   **规则**：这些允许开发人员设置多个测试的常见输入。

+   **运行器**：使用这些，您可以指定如何执行测试。

+   **参数**：这些允许使用多个输入执行测试方法。

+   **排序**：这些指定测试应该以何种顺序执行。

+   **匹配器**：这些允许您定义模式，然后用于验证测试对象的结果，或者帮助您控制模拟的行为。

在 Android Studio 中，创建新项目时，`app`模块会在 Gradle 中带有 JUnit 库。这应该在`app/build.gradle`中可见：

```kt
testImplementation 'junit:junit:4.13.1'
```

让我们看看我们需要测试的以下类：

```kt
class MyClass {
    fun factorial(n: Int): Int {
        return IntArray(n) {
            it+1
        }.reduce { acc, i ->
            acc * i
        }
    }
}
```

这个方法应该返回数字 `n` 的阶乘。我们可以从一个检查值的简单测试开始。为了创建一个新的单元测试，您需要在项目的 `test` 目录中创建一个新的类。大多数开发人员遵循的典型约定是在 `test` 目录中的相同包下为您的类名称添加 `Test` 后缀，并将其放在相同的包下。例如，`com.mypackage.ClassA` 将在 `com.mypackage.ClassATest` 中进行测试：

```kt
import org.junit.Assert.assertEquals
import org.junit.Test
class MyClassTest {
    private val myClass = MyClass()
    @Test
    fun computesFactorial() {
        val n = 3
        val result = myClass.factorial(n)
        assertEquals(6, result)
    }
}
```

在这个测试中，您可以看到我们初始化了被测试的类，测试方法本身使用了 `@Test` 注解。测试方法本身将断言 `(3!)==6`。断言使用了 JUnit 库中的 `assertEquals` 方法。开发中的一个常见做法是将测试分为三个区域，也称为 AAA（Arrange-Act-Assert）：

+   Arrange - 初始化输入的地方

+   Act - 调用被测试方法的地方

+   Assert - 验证的地方

我们可以编写另一个测试来确保值是正确的，但这意味着我们最终会重复代码。现在我们可以尝试编写一个参数化测试。为了做到这一点，我们需要使用参数化测试运行器。前面的测试有其自己的内置运行器，由 JUnit 提供。参数化运行器将为我们提供的不同值重复运行测试，并且看起来像下面这样。（请注意，出于简洁起见，已删除了导入语句。）

```kt
@RunWith(Parameterized::class)
class MyClassTest(
    private val input: Int,
    private val expected: Int
) {
    companion object {
        @Parameterized.Parameters
        @JvmStatic
        fun getData(): Collection<Array<Int>> = listOf(
            arrayOf(0, 1),
            arrayOf(1, 1),
            arrayOf(2, 2),
            arrayOf(3, 6),
            arrayOf(4, 24),
            arrayOf(5, 120)
        )
    }
    private val myClass = MyClass()
    @Test
    fun computesFactorial() {
        val result = myClass.factorial(input)
        assertEquals(expected, result)
    }
}
```

这实际上将运行六个测试。`@Parameterized` 注解的使用告诉 JUnit 这是一个具有多个参数的测试，并且还允许我们为测试添加一个构造函数，该构造函数将表示我们的阶乘函数的输入值和输出。然后我们使用 `@Parameterized.Parameters` 注解定义了一组参数。这个测试的每个参数都是一个单独的列表，包含输入和期望的输出。当 JUnit 运行这个测试时，它将为每个参数运行一个新的实例，然后执行测试方法。这将产生五个成功和一个失败的结果，当我们测试 *0!* 时会失败，这意味着我们发现了一个错误。我们从未考虑 *n = 0* 的情况。现在，我们可以回到我们的代码来修复失败。我们可以通过用 `fold` 函数替换 `reduce` 函数来做到这一点，`fold` 函数允许我们指定初始值为 `1`：

```kt
fun factorial(n: Int): Int {
        return IntArray(n) {
            it + 1
        }.fold(1, { acc, i -> acc * i })
    }
```

现在运行测试，它们都会通过。但这并不意味着我们在这里就完成了。有很多事情可能会出错。如果 `n` 是一个负数会发生什么？由于我们在处理阶乘，可能会得到非常大的数字。在我们的示例中，我们使用整数，这意味着整数在 *12!* 之后会溢出。通常情况下，我们会在 `MyClassTest` 类中创建新的测试方法，但由于使用了参数化运行器，我们所有的新方法都会运行多次，这将花费我们的时间，因此我们将创建一个新的测试类来检查我们的错误：

```kt
class MyClassTest2 {
    private val myClass = MyClass()
    @Test(expected = MyClass.FactorialNotFoundException::class)
    fun computeNegatives() {
        myClass.factorial(-10)
    }
}
```

这将导致被测试的类发生以下变化。

```kt
class MyClass {
    @Throws(FactorialNotFoundException::class)
    fun factorial(n: Int): Int {
        if (n < 0) {
            throw FactorialNotFoundException
        }
        return IntArray(n) {
            it + 1
        }.fold(1, { acc, i -> acc * i })
    }
    object FactorialNotFoundException : Throwable()
}
```

让我们解决非常大的阶乘的问题。我们可以使用 `BigInteger` 类，它能够容纳大数字。我们可以更新测试如下（未显示导入语句）：

```kt
@RunWith(Parameterized::class)
class MyClassTest(
    private val input: Int,
    private val expected: BigInteger
) {
    companion object {
        @Parameterized.Parameters
        @JvmStatic
        fun getData(): Collection<Array<Any>> = listOf(
            arrayOf(0, BigInteger.ONE),
            arrayOf(1, BigInteger.ONE),
            arrayOf(2, BigInteger.valueOf(2)),
            arrayOf(3, BigInteger.valueOf(6)),
            arrayOf(4, BigInteger.valueOf(24)),
            arrayOf(5, BigInteger.valueOf(120)),
            arrayOf(13, BigInteger("6227020800")),
            arrayOf(25, BigInteger("15511210043330985984000000"))
        )
    }
    private val myClass = MyClass()
    @Test
    fun computesFactorial() {
        val result = myClass.factorial(input)
        assertEquals(expected, result)
    }
}
```

现在被测试的类看起来像这样：

```kt
    @Throws(FactorialNotFoundException::class)
    fun factorial(n: Int): BigInteger {
        if (n < 0) {
            throw FactorialNotFoundException
        }
        return IntArray(n) {
            it + 1
        }.fold(BigInteger.ONE, { acc, i -> acc * i.toBigInteger() })
    }
```

在前面的示例中，我们使用 `IntArray` 实现了阶乘。这个实现更多地基于 Kotlin 能够将方法链接在一起的能力，但它有一个缺点：当不需要时它使用了数组的内存。我们只关心阶乘，而不是存储从 1 到 *n* 的所有数字。我们可以将实现更改为一个简单的 `for` 循环，并在重构过程中使用测试来指导我们。在您的应用程序中有测试的两个好处可以在这里观察到：

+   它们作为更新后的文档，说明了特性应该如何实现。

+   Android Studio 测试技巧

让我们更新代码，摆脱`IntArray`：

```kt
    @Throws(FactorialNotFoundException::class)
    fun factorial(n: Int): BigInteger {
        if (n < 0) {
            throw FactorialNotFoundException
        }
        var result = BigInteger.ONE
        for (i in 1..n){
            result = result.times(i.toBigInteger())
        }
        return result
    }
```

如果我们修改`factorial`函数，如前面的示例所示，并运行测试，我们应该看到它们都通过了。

在某些情况下，您的测试将使用测试或应用程序常见的资源（数据库、文件等）。理想情况下，这不应该发生在单元测试中，但总会有例外。让我们分析一下这种情况，看看 JUnit 如何帮助我们。我们将添加一个`companion`对象，它将存储结果，以模拟这种行为：

```kt
    companion object {
        var result: BigInteger = BigInteger.ONE
    }
    @Throws(FactorialNotFoundException::class)
    fun factorial(n: Int): BigInteger {
        if (n < 0) {
            throw FactorialNotFoundException
        }
        for (i in 1..n) {
            result = result.times(i.toBigInteger())
        }
        return result
    }
```

它们在重构代码时通过保持相同的断言并检测新的代码更改是否破坏了它来指导我们。

```kt
    @Before
    fun setUp(){
        MyClass.result = BigInteger.ONE
    }
    @After
    fun tearDown(){
        MyClass.result = BigInteger.ONE
    }
    @Test
    fun computesFactorial() {
        val result = myClass.factorial(input)
        assertEquals(expected, result)
    }
```

在测试中，我们添加了两个带有`@Before`和`@After`注解的方法。当引入这些方法时，JUnit 将按以下方式更改执行流程：所有带有`@Before`注解的方法将被执行，将执行带有`@Test`注解的方法，然后将执行所有带有`@After`注解的方法。这个过程将对类中的每个`@Test`方法重复执行。

如果您发现自己在`@Before`方法中重复相同的语句，可以考虑使用`@Rule`来消除重复。我们可以为前面的示例设置一个测试规则。测试规则应该在`test`或`androidTest`包中，因为它们的使用仅限于测试。它们往往用于多个测试中，因此可以将规则放在`rules`包中（未显示导入语句）：

```kt
class ResultRule : TestRule {
    override fun apply(
        base: Statement,
        description: Description?
    ): Statement? {
        return object : Statement() {
            @Throws(Throwable::class)
            override fun evaluate() {
                MyClass.result = BigInteger.ONE
                try {
                    base.evaluate()
                } finally {
                    MyClass.result = BigInteger.ONE
                }
            }
        }
    }
}
```

如果我们执行前面代码的测试，将开始看到一些测试失败。这是因为在第一个测试执行`factorial`函数后，结果将具有执行测试的值，当执行新测试时，阶乘的结果将乘以结果的先前值。通常，这是好的，因为测试告诉我们我们做错了什么，我们应该纠正这个问题，但是对于这个示例，我们将直接在测试中解决这个问题：

```kt
    @JvmField
    @Rule
    val resultRule = ResultRule()
    private val myClass = MyClass()
    @Test
    fun computesFactorial() {
        val result = myClass.factorial(input)
        assertEquals(expected, result)
    }
```

为了将规则添加到测试中，我们使用`@Rule`注解。由于测试是用 Kotlin 编写的，我们使用`@JvmField`来避免生成 getter 和 setter，因为`@Rule`需要一个公共字段而不是方法。

# ![图 9.2：Android Studio 中的测试输出

在前面的示例中，我们可以看到规则将实现`TestRule`，而`TestRule`又带有`apply()`方法。然后我们创建一个新的`Statement`对象，它将执行基本语句（测试本身）并在语句之前和之后重置结果的值。现在我们可以修改测试如下：Android Studio 提供了一套很好的快捷方式和可视化工具来帮助测试。如果要为类创建新的测试或转到类的现有测试，可以使用*Ctrl* + *Shift* + *T*（Windows）或*Command* + *Shift* + *T*（Mac）快捷键。要运行测试，有多种选项：右键单击文件或包，然后选择`Run Tests in...`选项，或者如果要独立运行测试，可以转到特定的测试方法并选择顶部的绿色图标，这将执行类中的所有测试；或者，对于单个测试，可以单击`@Test`注解方法旁边的绿色图标。这将触发测试执行，显示在`Run`选项卡中，如下截图所示。测试完成后，它们将变成红色或绿色，取决于它们的成功状态：Android Studio 提供了一套很好的快捷方式和可视化工具来帮助测试。如果要为类创建新的测试或转到类的现有测试，可以使用*Ctrl* + *Shift* + *T*（Windows）或*Command* + *Shift* + *T*（Mac）快捷键。要运行测试，有多种选项：右键单击文件或包，然后选择`Run Tests in...`选项，或者如果要独立运行测试，可以转到特定的测试方法并选择顶部的绿色图标，这将执行类中的所有测试；或者，对于单个测试，可以单击`@Test`注解方法旁边的绿色图标。这将触发测试执行，显示在`Run`选项卡中，如下截图所示。测试完成后，它们将变成红色或绿色，取决于它们的成功状态：图 9.2：Android Studio 中的测试输出在测试中可以找到的另一个重要功能是调试功能。这很重要，因为您可以调试测试和被测试的方法，所以如果在修复问题时遇到问题，您可以使用此功能查看测试使用的输入以及代码如何处理输入。您可以在测试旁边的绿色图标中找到的第三个功能是`Run With Coverage`选项。这有助于开发人员确定测试覆盖的代码行以及跳过的代码行。覆盖率越高，发现崩溃和错误的机会就越大：![图 9.3：Android Studio 中的测试覆盖率](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_03.jpg)

图 9.3：Android Studio 中的测试覆盖率

在上图中，您可以看到我们的类的覆盖范围，其中包括被测试的类的数量、被测试的方法的数量和被测试的行数。

另一种运行 Android 应用程序测试的方法是通过命令行。这通常在您的项目中有`Terminal`选项卡的情况下非常方便。`Terminal`选项卡通常位于 Android Studio 底部栏附近的`Logcat`选项卡附近。在每个 Android Studio 项目中，都有一个名为`gradlew`的文件。这是一个可执行文件，允许开发人员执行 Gradle 命令。为了运行本地单元测试，您可以使用以下命令：

+   `gradlew.bat test`（适用于 Windows）

+   `./gradlew test`（适用于 Mac 和 Linux）

执行该命令后，应用程序将被构建和测试。您可以在 Android Studio 右侧的`Gradle`选项卡中找到可以在`Terminal`中输入的各种命令。从`Terminal`或`Gradle`选项卡执行时，测试的输出可以在`app/build/reports`文件夹中找到：

![图 9.4：Android Studio 中的 Gradle 命令](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_04.jpg)

图 9.4：Android Studio 中的 Gradle 命令

# Mockito

在前面的示例中，我们看了如何设置单元测试以及如何使用断言来验证操作的结果。如果我们想要验证某个方法是否被调用呢？或者如果我们想要操纵测试输入以测试特定情景呢？在这些情况下，我们可以使用**Mockito**。这是一个帮助开发人员设置虚拟对象的库，可以将其注入到被测试的对象中，并允许它们验证方法调用、设置输入，甚至监视测试对象本身。

该库应该添加到您的`test` Gradle 设置中，如下所示：

```kt
testImplementation 'org.mockito:mockito-core:3.6.0'
```

现在，让我们看一下以下代码示例（请注意，为简洁起见，以下代码片段中的导入语句已被删除）：

```kt
class StringConcatenator(private val context: Context) {
    fun concatenate(@StringRes stringRes1: Int, 
      @StringRes stringRes2: Int): String {
      return context.getString(stringRes1).plus(context
          .getString(stringRes2))
    }
}
```

在这里，我们有`Context`对象，通常无法进行单元测试，因为它是 Android 框架的一部分。我们可以使用`mockito`创建一个测试替身，并将其注入到`StringConcatenator`对象中。然后，我们可以操纵对`getString()`的调用，以返回我们选择的任何输入。这个过程被称为模拟。

```kt
class StringConcatenatorTest {
    private val context = Mockito.mock(Context::class.java)
    private val stringConcatenator = StringConcatenator(context)
    @Test
    fun concatenate() {
        val stringRes1 = 1
        val stringRes2 = 2
        val string1 = "string1"
        val string2 = "string2"
        Mockito.`when`(context.getString(stringRes1)).thenReturn(string1)
        Mockito.`when`(context.getString(stringRes2)).thenReturn(string2)
        val result = stringConcatenator.concatenate(stringRes1,
            stringRes2)
        assertEquals(string1.plus(string2), result)
    }
}
```

注意

`` ` ``是 Kotlin 中的转义字符，不应与引号混淆。它允许开发人员为方法设置任何他们想要的名称，包括特殊字符或保留字。

在测试中，我们已经创建了一个`mock`上下文。当测试`concatenate`方法时，我们使用 Mockito 在调用特定输入的`getString()`方法时返回一个特定的字符串。这样我们就可以断言最终的结果。

Mockito 不仅限于仅模拟 Android Framework 类。我们可以创建一个`SpecificStringConcatenator`类，它将使用`StringConcatenator`从`strings.xml`中连接两个特定的字符串：

```kt
class SpecificStringConcatenator(private val stringConcatenator:   StringConcatenator) {
    fun concatenateSpecificStrings(): String {
        return stringConcatenator.concatenate(R.string.string_1,           R.string.string_2)
    }
}
```

我们可以这样为它编写测试：

```kt
class SpecificStringConcatenatorTest {
    private val stringConcatenator = Mockito
      .mock(StringConcatenator::class.java)
    private val specificStringConcatenator = 
      SpecificStringConcatenator(stringConcatenator)
    @Test
    fun concatenateSpecificStrings() {
        val expected = "expected"
        Mockito.'when'(stringConcatenator.concatenate(R.string.string_1, 
          R.string.string_2))
            .thenReturn(expected)
        val result = specificStringConcatenator
          .concatenateSpecificStrings()
        assertEquals(expected, result)
    }
}
```

在这里，我们模拟了先前的`StringConcatenator`并指示模拟返回一个特定的结果。如果我们运行测试，它将失败，因为 Mockito 仅限于模拟最终类。在这里，它遇到了与 Kotlin 冲突的问题，除非我们将类指定为*open*，否则所有类默认都是*final*。幸运的是，我们可以应用一个配置来解决这个问题，而不必使受测试的类为*open*：

1.  在`test`包中创建一个名为`resources`的文件夹。

1.  在`resources`文件夹中，创建一个名为`mockito-extensions`的文件夹。

1.  在`mockito-extensions`文件夹中，创建一个名为`org.mockito.plugins.MockMaker`的文件。

1.  在文件中，添加以下行：

```kt
    mock-maker-inline
    ```

在无法使用 JUnit 断言的回调或异步工作的情况下，可以使用`mockito`来验证对回调或 lambdas 的调用：

```kt
class SpecificStringConcatenator(private val stringConcatenator:   StringConcatenator) {
    fun concatenateSpecificStrings(): String {
        return stringConcatenator.concatenate(R.string.string_1,           R.string.string_2)
    }
    fun concatenateWithCallback(callback: Callback) {
        callback.onStringReady(concatenateSpecificStrings())
    }
    interface Callback {
        fun onStringReady(input: String)
    }
}
```

在上面的例子中，我们添加了`concatenateWithCallback`方法，它将使用`concatenateSpecificStrings`方法的结果来调用回调。对这个方法的测试将如下所示：

```kt
    @Test
    fun concatenateWithCallback() {
        val expected = "expected"
        Mockito.`when`(stringConcatenator.concatenate(R.string.string_1,           R.string.string_2))
            .thenReturn(expected)
        val callback =           Mockito.mock(SpecificStringConcatenator.Callback::class.java)
        specificStringConcatenator.concatenateWithCallback(callback)
        Mockito.verify(callback).onStringReady(expected)
    }
```

这里，我们创建了一个模拟的`Callback`对象，然后可以验证最终的预期结果。请注意，我们不得不重复设置`concatenateSpecificStrings`方法来测试`concatenateWithCallback`方法。您不应该模拟正在测试的对象；然而，您可以使用`spy`来更改它们的行为。我们可以对`stringConcatenator`对象进行监视，以改变`concatenateSpecificStrings`方法的结果：

```kt
    @Test
    fun concatenateWithCallback() {
        val expected = "expected"
        val spy = Mockito.spy(specificStringConcatenator)
        Mockito.`when`(spy.concatenateSpecificStrings())          .thenReturn(expected)
        val callback           = Mockito.mock(SpecificStringConcatenator.Callback::class.java)
        specificStringConcatenator.concatenateWithCallback(callback)
        Mockito.verify(callback).onStringReady(expected)
    }
```

Mockito 还依赖于依赖注入来初始化类变量，并且有一个自定义构建 JUnit 测试运行器。这可以简化我们变量的初始化，如下所示：

```kt
@RunWith(MockitoJUnitRunner::class)
class SpecificStringConcatenatorTest {
    @Mock
    lateinit var stringConcatenator: StringConcatenator
    @InjectMocks
    lateinit var specificStringConcatenator: SpecificStringConcatenator
}
```

在上面的例子中，`MockitoRunner`将使用`@Mock`注释的变量用模拟对象注入。接下来，它将创建一个新的非模拟实例字段，并用`@InjectionMocks`注释。当创建这个实例时，Mockito 将尝试注入符合该对象构造函数签名的模拟对象。

## mockito-kotlin

您可能已经注意到，在前面的示例中，来自 Mockito 的`when`方法已经转义。这是因为与 Kotlin 编程语言冲突。Mockito 主要是为 Java 构建的，当 Kotlin 创建时，它引入了这个关键字。类似这样的冲突可以使用`` ` ``字符。这个，连同其他一些小问题，导致在 Kotlin 中使用 Mockito 时有些不便。引入了一些库来包装 Mockito 并在使用时提供更好的体验。其中之一是`mockito-kotlin`。您可以使用以下命令将此库添加到您的模块中：

```kt
testImplementation "com.nhaarman.mockitokotlin2:mockito-kotlin:2.2.0"
```

这个库添加的一个明显的变化是用`whenever`替换`when`方法。另一个有用的变化是用泛型替换`mock`方法，而不是类对象。其余的语法与 Mockito 语法类似。

现在我们可以使用新的库更新之前的测试，从`StringConcatenatorTest`开始（为了简洁起见，导入语句已被删除）：

```kt
class StringConcatenatorTest {
    private val context = mock<Context>()
    private val stringConcatenator = StringConcatenator(context)
    @Test
    fun concatenate() {
        val stringRes1 = 1
        val stringRes2 = 2
        val string1 = "string1"
        val string2 = "string2"
        whenever(context.getString(stringRes1)).thenReturn(string1)
        whenever(context.getString(stringRes2)).thenReturn(string2)
        val result =           stringConcatenator.concatenate(stringRes1, stringRes2)
        assertEquals(string1.plus(string2), result)
    }
}
```

正如你所看到的，`` ` ``字符消失了，我们对`Context`对象的模拟初始化也简化了。我们可以对`SpecificConcatenatorTest`类应用同样的东西（为了简洁起见，已经删除了导入语句）:

```kt
@RunWith(MockitoJUnitRunner::class)
class SpecificStringConcatenatorTest {
    @Mock
    lateinit var stringConcatenator: StringConcatenator
    @InjectMocks
    lateinit var specificStringConcatenator: SpecificStringConcatenator
    @Test
    fun concatenateSpecificStrings() {
        val expected = "expected"
        whenever(stringConcatenator.concatenate(R.string.string_1,           R.string.string_2))
            .thenReturn(expected)
        val result =           specificStringConcatenator.concatenateSpecificStrings()
        assertEquals(expected, result)
    }
    @Test
    fun concatenateWithCallback() {
        val expected = "expected"
        val spy = spy(specificStringConcatenator)
        whenever(spy.concatenateSpecificStrings()).thenReturn(expected)
        val callback = mock<SpecificStringConcatenator.Callback>()
        specificStringConcatenator.concatenateWithCallback(callback)
        verify(callback).onStringReady(expected)
    }
}
```

## 练习 9.01: 测试数字的总和

使用 JUnit、Mockito 和 `mockito-kotlin` 为下面的类编写一组测试，这些测试应该覆盖以下场景：

+   断言`0`、`1`、`5`、`20`和`Int.MAX_VALUE`的值。

+   断言负数的结果。

+   修复代码，并用公式 *n*(n+1)/2* 替换数字的求和部分。

    注

    在整个练习过程中，未显示导入语句。要查看完整的代码文件，请参考[`packt.live/35TW8JI`](http://packt.live/35TW8JI)：

要测试的代码如下。

```kt
class NumberAdder {
    @Throws(InvalidNumberException::class)
    fun sum(n: Int, callback: (BigInteger) -> Unit) {
        if (n < 0) {
            throw InvalidNumberException
        }
        var result = BigInteger.ZERO
        for (i in 1..n){
          result = result.plus(i.toBigInteger())
        }
        callback(result)

    }
    object InvalidNumberException : Throwable()
}
```

执行以下步骤完成这个练习：

1.  让我们确保必要的库被添加到`app/build.gradle` 文件中：

```kt
     testImplementation 'junit:junit:4.13.1'
     testImplementation 'org.mockito:mockito-core:3.6.0'
     testImplementation 'com.nhaarman.mockitokotlin2:mockito-kotlin:2.2.0'
    ```

1.  创建一个名为`NumberAdder`的类，然后将上述代码复制到其中。

1.  将光标移动到新创建的类内部，然后使用 *Command* + *Shift* + *T* 或 *Ctrl* + *Shift* + *T* 创建一个名为`NumberAdderParameterTest`的测试类。

1.  在这个类内创建一个参数化测试，它将断言对`0`、`1`、`5`、`20`和`Int.MAX_VALUE`值的结果：

```kt
    @RunWith(Parameterized::class)
    class NumberAdderParameterTest(
        private val input: Int,
        private val expected: BigInteger
    ) {
        companion object {
            @Parameterized.Parameters
            @JvmStatic
            fun getData(): List<Array<out Any>> = listOf(
                arrayOf(0, BigInteger.ZERO),
                arrayOf(1, BigInteger.ONE),
                arrayOf(5, 15.toBigInteger()),
                arrayOf(20, 210.toBigInteger()),
                arrayOf(Int.MAX_VALUE, BigInteger("2305843008139952128"))
            )
        }
        private val numberAdder = NumberAdder()
        @Test
        fun sum() {
            val callback = mock<(BigInteger) -> Unit>()
            numberAdder.sum(input, callback)
            verify(callback).invoke(expected)
        }
    }
    ```

1.  创建一个专门处理负数抛出异常的测试类，名为`NumberAdderErrorHandlingTest`：

```kt
    @RunWith(MockitoJUnitRunner::class)
    class NumberAdderErrorHandlingTest {
        @InjectMocks
        lateinit var numberAdder: NumberAdder
        @Test(expected = NumberAdder.InvalidNumberException::class)
        fun sum() {
            val input = -1
            val callback = mock<(BigInteger) -> Unit>()
            numberAdder.sum(input, callback)
        }
    }
    ```

1.  由于 *1 + 2 + ...n = n * (n + 1) / 2*，我们可以在代码中使用这个公式，这将使方法的执行更快：

```kt
    class NumberAdder {
        @Throws(InvalidNumberException::class)
        fun sum(n: Int, callback: (BigInteger) -> Unit) {
            if (n < 0) {
                throw InvalidNumberException
            }
             callback(n.toBigInteger().times((n.toBigInteger() +            1.toBigInteger())).divide(2.toBigInteger()))
        }
        object InvalidNumberException : Throwable()
    }
    ```

通过右键单击测试所在的包并选择`Run all in [package_name]`来运行测试。将出现类似以下的输出，表示测试已通过：

![图 9.5: 练习 9.01 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_05.jpg)

图 9.5: 练习 9.01 的输出

通过完成这个练习，我们已经迈出了单元测试的第一步，成功为一个操作创建了多个测试用例，初步了解了 Mockito，并通过测试指导我们如何重构代码，而不引入新问题。

# 集成测试

假设您的项目已通过单元测试覆盖了大部分逻辑。现在您需要将这些经过测试的类添加到活动或片段中，并要求它们更新您的 UI。您如何确定这些类能够良好地协同工作？这个问题的答案就在于集成测试。这种测试的理念是确保应用程序内的不同组件能够良好地集成在一起。一些示例包括如下内容：

+   确保与您的存储组件良好地解析数据并进行良好的交互。  

+   存储组件能够正确地存储和检索数据。  

+   UI 组件加载和显示适当的数据。  

+   应用程序中不同屏幕之间的过渡。  

为了帮助集成测试，有时会以“给定 - 当 - 然后”格式编写要求。这些通常代表用户故事的验收标准。看下面的例子：  

```kt
Given I am not logged in
And I open the application
When I enter my credentials
And click Login
Then I see the Main screen
```

我们可以使用这些步骤来解决如何为正在开发的功能编写集成测试。  

在 Android 平台上，可以通过两个库实现集成测试：  

+   **Robolectric**：此库使开发人员能够对 Android 组件进行单元测试；也就是在没有实际设备或模拟器的情况下执行集成测试。  

+   **Espresso**：这个库对于在 Android 设备或模拟器上进行仪器测试非常有用。

我们将在下一节详细研究这些库。  

## Robolectric

Robolectric 最初是一个开源库，旨在让用户能够在本地测试中单元测试 Android 框架的类，而不是仪器测试的一部分。最近，它得到了 Google 的认可，并已与 AndroidX Jetpack 组件集成。该库的主要好处之一是简化了活动和碎片的测试。这在集成测试时也很有用，因为我们可以使用此功能确保我们的组件互相良好集成。一些 Robolectric 的特点如下：  

+   实例化和测试活动和碎片生命周期的可能性

+   测试视图膨胀的可能性  

+   为不同的 Android API、方向、屏幕大小、布局方向等提供配置的可能性  

+   改变`Application`类的可能性，从而有助于更改模块以允许插入数据模拟  

为了添加 Robolectric 以及 AndroidX 集成，我们需要以下库：  

```kt
    testImplementation 'org.robolectric:robolectric:4.3'
    testImplementation 'androidx.test.ext:junit:1.1.1'
```

第二个库将带来一组测试 Android 组件所需的`utility`方法和类。  

假设我们必须交付一个功能，其中我们显示文本`Result x`，其中`x`是用户将在`EditText`元素中插入的数字的阶乘函数。为了实现这一点，我们有两个类，一个计算阶乘，另一个是如果数字是正数，则将单词`Result`与阶乘连接起来，如果数字是负数，则返回文本`Error`。阶乘类将如下所示（在此示例中，为简洁起见，省略了导入语句）：  

```kt
class FactorialGenerator {
    @Throws(FactorialNotFoundException::class)
    fun factorial(n: Int): BigInteger {
        if (n < 0) {
            throw FactorialNotFoundException
        }
        var result = BigInteger.ONE
        for (i in 1..n) {
            result = result.times(i.toBigInteger())
        }
        return result
    }
    object FactorialNotFoundException : Throwable()
}
```

`TextFormatter`类将如下所示：  

```kt
class TextFormatter(
    private val factorialGenerator: FactorialGenerator,
    private val context: Context
) {
    fun getFactorialResult(n: Int): String {
        return try {
            context.getString(R.string.result,               factorialGenerator.factorial(n).toString())
        } catch (e: FactorialGenerator.FactorialNotFoundException) {
            context.getString(R.string.error)
        }
    }
}
```

我们可以在我们的活动中组合这两个组件，类似于这样：  

```kt
class MainActivity : AppCompatActivity() {
    private lateinit var textFormatter: TextFormatter
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        ttextFormatter = TextFormatter(FactorialGenerator(), 
          applicationContext)
        findViewById<Button>(R.id.button).setOnClickListener {
            findViewById<TextView>(R.id.text_view).text               = textFormatter.getFactorialResult(findViewById<EditText>                (R.id.edit_text).text.toString().toInt())
        }
    }
}
```

在这种情况下，我们可以观察到三个组件相互作用。我们可以使用 Robolectric 来测试我们的 activity。通过测试创建组件的 activity，我们还可以测试这三个组件之间的交互。我们可以编写如下的测试：

```kt
@RunWith(AndroidJUnit4::class)
class MainActivityTest {
    private val context = getApplicationContext<Application>()
    @Test
    fun `show factorial result in text view`() {
        val scenario = launch<MainActivity>(MainActivity::class.java)
        scenario.moveToState(Lifecycle.State.RESUMED)
        scenario.onActivity { activity ->
            activity.edit_text.setText(5.toString())
            activity.button.performClick()
            assertEquals(context.getString(R.string.result,               "120"),activity.text_view.text)
        }
    }
}
```

在前面的例子中，我们可以看到 AndroidX 对 activity 测试的支持。`AndroidJUnit4` 测试运行器将设置 Robolectric 并创建必要的配置，而 `launch` 方法将返回一个 `scenario` 对象，我们可以通过这个对象来实现测试所需的条件。

如果我们想为测试添加配置，可以在类和每个测试方法上使用 `@Config` 注释：

```kt
@Config(
    sdk = [Build.VERSION_CODES.P],
    minSdk = Build.VERSION_CODES.KITKAT,
    maxSdk = Build.VERSION_CODES.Q,
    application = Application::class,
    assetDir = "/assetDir/"
)
@RunWith(AndroidJUnit4::class)
class MainActivityTest 
```

我们也可以在 `test/resources` 文件夹中的 `robolectric.properties` 文件中指定全局配置，就像这样：

```kt
sdk=28
minSdk = 14
maxSdk = 29
```

最近添加到 Robolectric 的另一个重要功能是对 Espresso 库的支持。这允许开发人员使用 Espresso 的语法与视图进行交互并对视图进行断言。可以与 Robolectric 结合使用的另一个库是 `FragmentScenario`，它允许测试片段的可能性。可以通过以下方式在 Gradle 中添加这些库：

```kt
    testImplementation 'androidx.fragment:fragment-testing:1.1.0'
    testImplementation 'androidx.test.espresso:espresso-core:3.2.0'
```

使用 `scenario` 设置测试片段与使用 `scenario` 设置测试活动类似：

```kt
val scenario = launchFragmentInContainer<MainFragment>()
scenario.moveToState(Lifecycle.State.CREATED)
```

## Espresso

Espresso 是一个旨在以简洁方式执行交互和断言的库。最初设计为用于仪表化测试，现在已迁移到与 Robolectric 一起使用。执行操作的典型用法如下：

```kt
onView(Matcher<View>).perform(ViewAction)
```

用于验证，我们可以使用以下内容：

```kt
onView(Matcher<View>).check(ViewAssertion)
```

如果在 `ViewMatchers` 类中找不到自定义的 `ViewMatchers`，我们可以自定义。其中最常见的是 `withId` 和 `withText`。这两个允许我们基于它们的 `R.id.myId` 标识符或文本标识符识别视图。理想情况下，第一个应该用于识别特定的视图。Espresso 的另一个有趣之处是依赖于 `Hamcrest` 库进行匹配。这是一个旨在改进测试的 Java 库。如果必要，这允许组合多个匹配器。比如说，您的 UI 上具有相同的 ID，可以使用以下表达式缩小搜索范围以找到特定视图：

```kt
onView(allOf(withId(R.id.edit_text), withParent(withId(R.id.root))))
```

`allOf` 表达式将评估所有其他操作符，并且只有在内部所有操作符都通过时才会通过。前述的表达式将转换为“找到具有 `id=edit_text` 的父视图为 `id=R.id.root` 的视图。” 其他 `Hamcrest` 操作符可能包括 `anyOf`, `both`, `either`, `is`, `isA`, `hasItem`, `equalTo`, `any`, `instanceOf`, `not`, `null` 和 `notNull`。

`ViewActions` 与 `ViewMatchers` 有类似的方法。我们可以在 `ViewActions` 类中找到常见的方法。常见的包括 `typeText`、`click`、`scrollTo`、`clearText`、`swipeLeft`、`swipeRight`、`swipeUp`、`swipeDown`、`closeSoftKeyboard`、`pressBack`、`pressKey`、`doubleClick` 和 `longClick`。如果您有自定义视图并且需要特定操作，则可以通过实现 `ViewAction` 接口来实现自己的 `ViewAction` 元素。

与前面的示例类似，`ViewAssertions` 有自己的类。通常，可以使用 `matches` 方法，然后使用 `ViewMatchers` 和 `Hamcrest` 匹配器来验证结果：

```kt
onView(withId(R.id.text_view)).check(matches(withText("My text")))) 
```

前面的示例将验证具有 `text_view` ID 的视图中是否包含文本 `My text`：

```kt
onView(withId(R.id.button)).perform(click())
```

这将点击具有 ID 按钮的视图。

现在我们可以重写 Robolectric 测试并添加 Espresso，这将给我们带来以下内容（未显示导入语句）：

```kt
@RunWith(AndroidJUnit4::class)
class MainActivityTest {
    @Test
    fun `show factorial result in text view`() {
        val scenario = launch<MainActivity>(MainActivity::class.java)
        scenario.moveToState(Lifecycle.State.RESUMED)
        scenario.onActivity { activity ->
            onView(withId(R.id.edit_text)).perform(typeText("5"))
            onView(withId(R.id.button)).perform(click())
            onView(withId(R.id.text_view))
              .check(matches(withText(activity                 .getString(R.string.result, "120"))))
        }
    }
}
```

在前面的代码示例中，我们可以观察到如何使用 Espresso 输入数字 `5` 到 `EditText` 中，然后点击按钮，然后使用 `onView()` 方法获取到 `TextView` 中显示的文本，并使用 `perform()` 执行操作或使用 `check()` 进行断言。

注意

对于以下练习，您需要一个启用了 USB 调试的模拟器或实际设备。您可以通过在 Android Studio 中选择 `工具` | `AVD 管理器` 来创建一个，然后选择 `创建虚拟设备` 选项，并选择虚拟机类型，点击 `下一步`，然后选择 x86 映像。对于此练习来说，任何大于 Lollipop 的映像都应该可以。接下来，您可以给您的映像命名并单击 `完成`。

## 练习 9.02：双重积分

开发一个应用程序，观察以下要求：

```kt
Given I open the application
And I insert the number n
When I press the Calculate button
Then I should see the text "The sum of numbers from 1 to n is [result]"
Given I open the application
And I insert the number -n
When I press the Calculate button
Then I should see the text "Error: Invalid number"
```

您应该使用 Robolectric 和 Espresso 实现单元测试和集成测试，并将集成测试迁移到成为仪器化测试。

注意

在整个练习的过程中，我们没有显示导入语句。要查看完整的代码文件，请参考[`packt.live/2M1MtcY`](http://packt.live/2M1MtcY)：

实施以下步骤来完成此练习：

1.  让我们首先将必要的测试库添加到 `app/build.gradle` 中：

```kt
        testImplementation 'junit:junit:4.13.1'
        testImplementation 'org.mockito:mockito-core:3.6.0'
        testImplementation 'com.nhaarman.mockitokotlin2
          :mockito-kotlin:2.2.0'
        testImplementation 'org.robolectric:robolectric:4.4'
        testImplementation 'androidx.test.ext:junit:1.1.2'
        testImplementation 'androidx.test.espresso:espresso-core:3.3.0'
        androidTestImplementation 'androidx.test.ext:junit:1.1.2'
        androidTestImplementation 'androidx.test
          .espresso:espresso-core:3.3.0'
        androidTestImplementation 'androidx.test:rules:1.3.0'
    ```

1.  对于 Robolectric，我们需要添加额外的配置，首先在 `android` 闭包中的 `app/build.gradle` 中添加以下行：

```kt
    testOptions.unitTests.includeAndroidResources = true
    ```

1.  在 `test` 包中创建一个名为 `resources` 的目录。

1.  添加 `robolectric.properties` 文件，并在该文件中添加以下配置：

```kt
    sdk=28
    ```

1.  在 `test` 包中创建一个名为 `resources` 的文件夹。

1.  在 `resources` 中，创建一个名为 `mockito-extensions` 的文件夹。

1.  在 `mockito-extensions` 文件夹中，创建一个名为 `org.mockito.plugins.MockMaker` 的文件，并在文件中添加以下行：

```kt
    mock-maker-inline
    ```

1.  创建 `NumberAdder` 类。这与 *练习 9.01* 中的类似：

```kt
    import java.math.BigInteger
    class NumberAdder {
        @Throws(InvalidNumberException::class)
        fun sum(n: Int, callback: (BigInteger) -> Unit) {
            if (n < 0) {
                throw InvalidNumberException
            }
            callback(n.toBigInteger().times((n.toLong()           + 1).toBigInteger()).divide(2.toBigInteger()))
        }
        object InvalidNumberException : Throwable()
    }
    ```

1.  在 `test` 文件夹中为 `NumberAdder` 创建测试。首先，创建 `NumberAdderParameterTest`：

```kt
    @RunWith(Parameterized::class)
    class NumberAdderParameterTest(
        private val input: Int,
        private val expected: BigInteger
    ) {
        companion object {
            @Parameterized.Parameters
            @JvmStatic
            fun getData(): List<Array<out Any>> = listOf(
                arrayOf(0, BigInteger.ZERO),
                arrayOf(1, BigInteger.ONE),
                arrayOf(5, 15.toBigInteger()),
                arrayOf(20, 210.toBigInteger()),
                arrayOf(Int.MAX_VALUE, BigInteger("2305843008139952128"))
            )
        }
        private val numberAdder = NumberAdder()
        @Test
        fun sum() {
            val callback = mock<(BigInteger) -> Unit>()
            numberAdder.sum(input, callback)
            verify(callback).invoke(expected)
        }
    }
    ```

1.  然后，创建`NumberAdderErrorHandlingTest`测试：

```kt
    @RunWith(MockitoJUnitRunner::class)
    class NumberAdderErrorHandlingTest {
        @InjectMocks
        lateinit var numberAdder: NumberAdder
        @Test(expected = NumberAdder.InvalidNumberException::class)
        fun sum() {
            val input = -1
            val callback = mock<(BigInteger) -> Unit>()
            numberAdder.sum(input, callback)
        }
    }
    ```

1.  创建一个将总和格式化并与必要的字符串连接的类：

```kt
    class TextFormatter(
        private val numberAdder: NumberAdder,
        private val context: Context
    ) {
        fun getSumResult(n: Int, callback: (String) -> Unit) {
            try {
                numberAdder.sum(n) {
                    callback(
                        context.getString(
                            R.string.the_sum_of_numbers_from_1_to_is,
                            n,
                            it.toString()
                        )
                    )
                }
            } catch (e: NumberAdder.InvalidNumberException) {
                callback(context.getString
                  (R.string.error_invalid_number))
            }
        }
    }
    ```

1.  为这个类的成功和错误情况进行单元测试。从成功场景开始：

```kt
    @RunWith(MockitoJUnitRunner::class)
    class TextFormatterTest {
        @InjectMocks
        lateinit var textFormatter: TextFormatter
        @Mock
        lateinit var numberAdder: NumberAdder
        @Mock
        lateinit var context: Context
        @Test
        fun getSumResult_success() {
            val n = 10
            val sumResult = BigInteger.TEN
            val expected = "expected"
            whenever(numberAdder.sum(eq(n), any())).thenAnswer {
                (it.arguments[1] as (BigInteger)->Unit)
                    .invoke(sumResult)
            }
            whenever(context.getString
              (R.string.the_sum_of_numbers_from_1_to_is, n, 
                sumResult.toString())).thenReturn(expected)
            val callback = mock<(String)->Unit>()
            textFormatter.getSumResult(n, callback)
            verify(callback).invoke(expected)
        }
    ```

然后，为错误场景创建测试：

```kt
        @Test
        fun getSumResult_error() {
            val n = 10
            val expected = "expected"
            whenever(numberAdder.sum(eq(n),           any())).thenThrow(NumberAdder.InvalidNumberException)
            whenever(context.getString(R.string.error_invalid_number))          .thenReturn(expected)
            val callback = mock<(String)->Unit>()
            textFormatter.getSumResult(n, callback)
            verify(callback).invoke(expected)
        }
    }
    ```

1.  为`activity_main.xml`创建布局：

```kt
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:id="@+id/root"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical">
        <EditText
            android:id="@+id/edit_text"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:inputType="number" />
        <Button
            android:id="@+id/button"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_gravity="center_horizontal"
            android:text="@string/calculate" />
        <TextView
            android:id="@+id/text_view"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_gravity="center_horizontal" />
    </LinearLayout>
    ```

1.  创建包含所有其他组件的`MainActivity`类：

```kt
    class MainActivity : AppCompatActivity() {
        private lateinit var textFormatter: TextFormatter

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_main)
            textFormatter = TextFormatter(NumberAdder(), applicationContext)
            findViewById<Button>(R.id.button).setOnClickListener {
                textFormatter.getSumResult(findViewById<EditText>              (R.id.edit_text).text.toString().toIntOrNull() ?: 0) {
                    findViewById<TextView>(R.id.text_view).text = it
                }
            }
        }
    }
    ```

1.  创建`MainActivity`的测试，并将其放在`test`目录中。它将包含两个测试方法，一个用于成功，一个用于错误：

```kt
    @RunWith(AndroidJUnit4::class)
    class MainActivityTest {
        @Test
        fun `show sum result in text view`() {
            val scenario = launch<MainActivity>(MainActivity::class.java)
            scenario.moveToState(Lifecycle.State.RESUMED)
            scenario.onActivity { activity ->
                onView(withId(R.id.edit_text)).perform(replaceText("5"))
                onView(withId(R.id.button)).perform(click())
                onView(withId(R.id.text_view)).check(matches(withText
                 (activity.getString
                   (R.string.the_sum_of_numbers_from_1_to_is, 5, "15"))))
            }
        }
        @Test
        fun `show error in text view`() {
            val scenario = launch<MainActivity>(MainActivity::class.java)
            scenario.moveToState(Lifecycle.State.RESUMED)
            scenario.onActivity { activity ->
                onView(withId(R.id.edit_text))
                    .perform(replaceText("-5"))
                onView(withId(R.id.button)).perform(click())
                onView(withId(R.id.text_view)).check(
                    matches(withText(activity.getString(
                    R.string.error_invalid_number))))
            }
        }
    }
    ```

如果你通过右键单击包含测试的包并选择“在[package_name]中全部运行”来运行测试，那么会出现类似以下的输出：

![图 9.6：执行 Exercise 9.02 test 文件夹中的测试的结果](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_06.jpg)

图 9.6：执行 Exercise 9.02 test 文件夹中的测试的结果

如果你执行前面的测试，你应该会看到类似*图 9.6*的输出。Robolectric 测试的执行方式与常规单元测试相同；但是，执行时间会增加。

1.  现在让我们将前面的测试迁移到一个有仪器的集成测试中。为了做到这一点，我们将把前面的测试从`test`包复制到`androidTest`包，并删除我们的测试中与场景相关的代码。复制文件之后，我们将使用`ActivityTestRule`，它将在每次测试执行之前启动我们的活动。我们还需要重命名类以避免重复，并且重命名测试方法，因为这种语法不支持仪器化测试：

```kt
    @RunWith(AndroidJUnit4::class)
    class MainActivityUiTest {
        @JvmField
        @Rule
        var activityRule: ActivityTestRule<MainActivity> = 
          ActivityTestRule(MainActivity::class.java)
        @Test
        fun showSumResultInTextView() {
            activityRule.activity.let { activity ->
                onView(withId(R.id.edit_text)).perform(replaceText("5"))
                onView(withId(R.id.button)).perform(click())
                onView(withId(R.id.text_view)).check(matches
                 (withText(activity.getString
                  (R.string.the_sum_of_numbers_from_1_to_is, 5, "15"))))
            }
        }
        @Test
        fun showErrorInTextView() {
            activityRule.activity.let { activity ->
                onView(withId(R.id.edit_text)).perform(replaceText("-5"))
                onView(withId(R.id.button)).perform(click())
                onView(withId(R.id.text_view)).check(matches               (withText(activity.getString                 (R.string.error_invalid_number))))
            }
        }
    }
    ```

    如果你通过右键单击包含测试的包并选择“在[package_name]中全部运行”来运行测试，那么会出现类似以下的输出：

![图 9.7：执行 Exercise 9.02 androidTest 文件夹中的测试的结果](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_07.jpg)

图 9.7：执行 Exercise 9.02 androidTest 文件夹中的测试的结果

在*图 9.7*中，我们可以看到 Android Studio 显示的结果输出。如果你在测试执行时仔细观察仿真器，你会发现对于每个测试，你的活动都会被打开，输入会被设置在字段中，并且按钮会被点击。我们的集成测试（在工作站和仿真器上）都尝试匹配需求的接受标准。集成测试验证相同的行为，唯一的区别是一个在本地检查，另一个在 Android 设备或仿真器上检查。这里的主要好处是 Espresso 能够弥合它们之间的鸿沟，使得集成测试更容易设置和执行。

# UI 测试

UI 测试是开发人员可以模拟用户行程并验证应用程序不同模块之间的交互的测试，也被称为端到端测试。对于小型应用程序，您可以拥有一个测试套件，但对于较大的应用程序，您应该分割您的测试套件以覆盖特定的用户行程（登录，创建账户，设置流程等）。因为它们在设备上执行，所以您需要在`androidTest`包中编写它们，这意味着它们将使用**Instrumentation**框架来运行。Instrumentation 的工作方式如下：

+   应用程序已构建并安装在设备上。

+   将在设备上安装一个测试应用程序，用于监视您的应用程序。

+   测试应用程序将执行对您的应用程序的测试并记录结果。

其中一个缺点是测试将共享持久化数据，因此如果一个测试在设备上存储数据，那么第二个测试可以访问该数据，这意味着存在失败的风险。另一个缺点是，如果测试遭遇崩溃，这将停止整个测试，因为被测试的应用程序已经停止。在 Jetpack 更新中引入了`app/build.gradle`文件来解决这些问题：

```kt
android {
    ...
    defaultConfig {
        ...
        testInstrumentationRunner           "androidx.test.runner.AndroidJUnitRunner"
        testInstrumentationRunnerArguments clearPackageData: 'true'
    }
    testOptions {
        execution 'ANDROIDX_TEST_ORCHESTRATOR'
    }
}
dependencies {
    ...
    androidTestUtil 'androidx.test:orchestrator:1.3.0'
}
```

您可以使用 Gradle 的`connectedCheck`命令在连接的设备上执行协调器测试，无论是从`Terminal`还是从 Gradle 命令列表中。

在配置中，您将注意到以下行：`testInstrumentationRunner`。这使我们能够为测试创建自定义配置，这给了我们机会将模拟数据注入到模块中：

```kt
testInstrumentationRunner "com.android.CustomTestRunner"
```

`CustomTestRunner`如下（以下代码段未显示导入语句）：

```kt
class CustomTestRunner: AndroidJUnitRunner() {
    @Throws(Exception::class)
    override fun newApplication(
        cl: ClassLoader?,
        className: String?,
        context: Context?
    ): Application? {
        return super.newApplication(cl,           MyApplication::class.java.name, context)
    }
}
```

测试类本身可以通过应用 JUnit4 语法，并借助`androidx.test.ext.junit.runners.AndroidJUnit4`测试运行程序来编写：

```kt
@RunWith(AndroidJUnit4::class)
class MainActivityUiTest {
}
```

来自 AndroidX 测试支持的另一个重要功能是活动规则。当使用默认构造函数时，此规则将在每次测试之前启动活动，并准备好进行交互和断言：

```kt
    @JvmField
    @Rule
    var activityRule: ActivityTestRule<MainActivity>       = ActivityTestRule(MainActivity::class.java)
```

您还可以使用规则来避免启动活动，并自定义用于启动测试的意图：

```kt
    @JvmField
    @Rule
    var activityRule: ActivityTestRule<MainActivity> =       ActivityTestRule(MainActivity::class.java, false ,false)
    @Test
    fun myTestMethod() {
        val myIntent = Intent()
        activityRule.launchActivity(myIntent)
    }
```

`@Test`方法本身在专用测试线程中运行，这就是为什么类似 Espresso 这样的库很有用。Espresso 将自动将与 UI 线程上的视图的每次交互移动。Espresso 可以与 Robolectric 测试一样用于 UI 测试：

```kt
    @Test
    fun myTest() {
        onView(withId(R.id.edit_text)).perform(replaceText("5"))
        onView(withId(R.id.button)).perform(click())
        onView(withId(R.id.text_view))          .check(matches(withText("my test")))
    }
```

通常，在 UI 测试中，您将发现可能重复的交互和断言。为了避免在您的代码中重复多个场景，您可以应用一种称为`Robot`类的模式，其中交互和断言可以分组到特定方法中。您的测试代码将使用这些机器人并进行断言。典型的机器人看起来会像这样：

```kt
class MyScreenRobot {
    fun setText(): MyScreenRobot {
        onView(ViewMatchers.withId(R.id.edit_text))          .perform(ViewActions.replaceText("5"))
        return this
    }
    fun pressButton(): MyScreenRobot {
        onView(ViewMatchers.withId(R.id.button))          .perform(ViewActions.click())
        return this
    }
    fun assertText(): MyScreenRobot {
        onView(ViewMatchers.withId(R.id.text_view))          .check(ViewAssertions.matches(ViewMatchers           .withText("my test")))
        return this
    }
}
```

测试结果将如下所示：

```kt
    @Test
    fun myTest() {
       MyScreenRobot()
           .setText()
           .pressButton()
           .assertText()
    }
```

因为应用程序可能是多线程的，有时需要一段时间从各种来源（互联网、文件、本地存储等）加载数据，UI 测试将必须知道何时 UI 可用以进行交互。一个实现这一点的方法是通过使用空闲资源。这些是可以在测试之前向 Espresso 注册并注入到您的应用程序组件中的对象，在这些组件中进行多线程工作。应用程序将在工作进行中将它们标记为非空闲，并且当工作完成时为空闲。正是在这一点上，Espresso 将开始执行测试。其中最常用的之一是`CountingIdlingResource`。这个特定的实现使用一个计数器，在您希望 Espresso 等待您的代码完成执行时应该增加它，并在您希望让 Espresso 验证您的代码时减少它。当计数器达到`0`时，Espresso 将恢复测试。具有空闲资源的组件示例看起来像这样：

```kt
class MyHeavyliftingComponent(private val   countingIdlingResource:CountingIdlingResource) {
    fun doHeavyWork() {
        countingIdlingResource.increment()
        // do work
        countingIdlingResource.decrement()
    }
}
```

`Application`类可以用来注入空闲资源，就像这样：

```kt
class MyApplication : Application(){
    val countingIdlingResource = CountingIdlingResource("My heavy work")
    val myHeavyliftingComponent =       MyHeavyliftingComponent(countingIdlingResource)
}
```

然后，在测试中，我们可以访问`Application`类并将资源注册到 Espresso：

```kt
@RunWith(AndroidJUnit4::class)
class MyTest {
    @Before
    fun setUp() {
        val myApplication = getApplicationContext<MyApplication>()
        IdlingRegistry.getInstance()          .register(myApplication.countingIdlingResource)
    }
}
```

Espresso 配备了一组扩展，可用于断言不同的 Android 组件。其中一种扩展是意图测试。在想要单独测试活动时（更适用于集成测试）这将会很有用。为了使用它，您需要将该库添加到 Gradle 中：

```kt
androidTestImplementation 'androidx.test.espresso:espresso-intents:3.3.0'
```

添加完库后，您需要使用`IntentsTestRule`来设置必要的意图监控。该规则是`ActivityTestRule`的子类：

```kt
    @JvmField
    @Rule
    var intentsRule: IntentsTestRule<MainActivity>       = IntentsTestRule(MainActivity::class.java)
```

为了断言意图的值，您需要触发适当的操作，然后使用`intended`方法：

```kt
        onView(withId(R.id.button)).perform(click())
        intended(allOf(
            hasComponent(hasShortClassName(".MainActivity")),
            hasExtra(MainActivity.MY_EXTRA, "myExtraValue")))
```

`intended`方法的工作方式类似于`onView`方法。它需要一个可以与`Hamcrest`匹配器组合的匹配器。与 Intent 相关的匹配器可以在`IntentMatchers`类中找到。该类包含了断言`Intent`类的不同方法：extras、data、components、bundles 等等。

另一个重要的扩展库来帮助`RecyclerView`。Espresso 的`onData`方法只能测试`AdapterViews`，如`ListView`，而不能断言`RecyclerView`。为了使用该扩展，您需要向项目中添加以下库：

```kt
androidTestImplementation   'com.android.support.test.espresso:espresso-contrib:3.0.2'
```

该库提供了一个`RecyclerViewActions`类，其中包含一组方法，允许您对`RecyclerView`内的项目执行操作：

```kt
onView(withId(R.id.recycler_view))  .perform(RecyclerViewActions.actionOnItemAtPosition(0, click()))
```

前面的语句将点击位置为`0`的项目：

```kt
onView(withId(R.id.recycler_view)).perform(RecyclerViewActions   .scrollToPosition<RecyclerView.ViewHolder>(10))
```

这将滚动到列表中的第十个项目：

```kt
onView(withText("myText")).check(matches(isDisplayed()))
```

前面的代码将检查是否显示了带有`myText`文本的视图，这也适用于`RecyclerView`项。

## 练习 9.03：随机等待时间

编写一个应用程序，它将有两个屏幕。第一个屏幕将有一个按钮。当用户按下按钮时，它将等待 1 到 5 秒之间的随机时间，然后启动显示文本`x 秒后打开`的第二屏幕，其中`x`是经过的秒数。编写一个 UI 测试，以覆盖此场景，并调整以下特性以用于测试：

+   当运行测试时，`random`函数将返回值`1`。

+   `CountingIdlingResource`将用于指示计时器何时停止。

注意

在本练习中，未显示导入语句。要查看完整的代码文件，请参考[`packt.live/38V7krh`](http://packt.live/38V7krh)。

进行以下步骤来完成这个练习：

1.  将以下库添加到`app/build.gradle`：

```kt
        implementation 'androidx.test.espresso:espresso-core:3.3.0'
        testImplementation 'junit:junit:4.13.1'
        androidTestImplementation 'androidx.test.ext:junit:1.1.2'
        androidTestImplementation 'androidx.test:rules:1.3.0'
    ```

1.  然后，从`Randomizer`类开始：

```kt
    class Randomizer(private val random: Random) {
        fun getTimeToWait(): Int {
            return random.nextInt(5) + 1
        }
    }
    ```

1.  接下来，创建一个`Synchronizer`类，它将使用`Randomizer`和`Timer`等待随机时间间隔。它还将使用`CountingIdlingResource`来标记任务的开始和结束：

```kt
    class Synchronizer(
        private val randomizer: Randomizer,
        private val timer: Timer,
        private val countingIdlingResource: CountingIdlingResource
    ) {
        fun executeAfterDelay(callback: (Int) -> Unit) {
            val timeToWait = randomizer.getTimeToWait()
            countingIdlingResource.increment()
            timer.schedule(CallbackTask(callback, timeToWait),           timeToWait * 1000L)
        }
        inner class CallbackTask(
            private val callback: (Int) -> Unit,
            private val time: Int
        ) : TimerTask() {
            override fun run() {
                callback(time)
                countingIdlingResource.decrement()
            }
        }
    }
    ```

1.  现在创建一个`Application`类，负责创建前述所有类的实例：

```kt
    class MyApplication : Application() {
        val countingIdlingResource =       CountingIdlingResource("Timer resource")
        val randomizer = Randomizer(Random())
        val synchronizer = Synchronizer(randomizer, Timer(),       countingIdlingResource)
    }
    ```

1.  将`MyApplication`类添加到`AndroidManifest`中`application`标签中，带有`android:name`属性。

1.  创建一个`activity_1`布局文件，其中包含一个父布局和一个按钮：

```kt
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical">

        <Button
            android:id="@+id/activity_1_button"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_gravity="center"
            android:text="@string/press_me" />
    </LinearLayout>
    ```

1.  创建一个包含父布局和`TextView`的`activity_2`布局文件：

```kt
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical">
        <TextView
            android:id="@+id/activity_2_text_view"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_gravity="center" />
    </LinearLayout>
    ```

1.  创建`Activity1`类，它将实现按钮点击的逻辑：

```kt
    class Activity1 : AppCompatActivity() {
        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_1)
            findViewById<Button>(R.id.activity_1_button)
              .setOnClickListener {
                (application as MyApplication).synchronizer
                  .executeAfterDelay {
                    startActivity(Activity2.newIntent(this, it))
                }
            }
        }
    }
    ```

1.  创建`Activity2`类，它将通过意图显示接收到的数据：

```kt
    class Activity2 : AppCompatActivity() {
        companion object {
            private const val EXTRA_SECONDS = "extra_seconds"
            fun newIntent(context: Context, seconds: Int) =
                Intent(context, Activity2::class.java).putExtra(
                    EXTRA_SECONDS, seconds
                )
        }
        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_2)
            findViewById<TextView>(R.id.activity_2_text_view).text =
                getString(R.string.opened_after_x_seconds,               intent.getIntExtra(EXTRA_SECONDS, 0))
        }
    }
    ```

1.  在`androidTest`目录中创建一个`FlowTest`类，它将注册`MyApplication`对象的`IdlingResource`并断言点击的结果：

```kt
    @RunWith(AndroidJUnit4::class)
    @LargeTest
    class FlowTest {
        @JvmField
        @Rule
        var activityRule: ActivityTestRule<Activity1> =       ActivityTestRule(Activity1::class.java)
        private val myApplication = getApplicationContext<MyApplication>()
        @Before
        fun setUp() {
            IdlingRegistry.getInstance().register(myApplication           .countingIdlingResource)
        }
        @Test
        fun verifyFlow() {
            onView(withId(R.id.activity_1_button)).perform(click())
            onView(withId(R.id.activity_2_text_view))          .check(matches(withText(myApplication             .getString(R.string.opened_after_x_seconds, 1))))
        }
    }
    ```

1.  多次运行测试并检查测试结果。请注意，测试有 20%的成功机会，但它将等待按钮被点击。这意味着闲置资源正在工作。还要观察这里存在随机因素。

1.  测试不喜欢随机性，所以我们需要通过使`Randomizer`类为开放的，并在`androidTest`目录中创建一个子类来消除它。我们可以对`MyApplication`类做同样的事情，并提供一个称为`TestRandomizer`的不同随机器：

```kt
    class TestRandomizer(random: Random) : Randomizer(random) {
        override fun getTimeToWait(): Int {
            return 1
        }
    }
    ```

1.  现在，以一种我们可以从子类中重写随机器的方式修改`MyApplication`类：

```kt
    open class MyApplication : Application() {
        val countingIdlingResource =       CountingIdlingResource("Timer resource")
        lateinit var synchronizer: Synchronizer
        override fun onCreate() {
            super.onCreate()
            synchronizer = Synchronizer(createRandomizer(), Timer(),           countingIdlingResource)
        }
        open fun createRandomizer() = Randomizer(Random())
    }
    ```

1.  在`androidTest`目录中，创建`TestMyApplication`，它将扩展`MyApplication`并重写`createRandomizer`方法：

```kt
    class TestMyApplication : MyApplication() {
        override fun createRandomizer(): Randomizer {
            return TestRandomizer(Random())
        }
    }
    ```

1.  最后，创建一个仪表测试运行器，其将在测试内使用这个新的`Application`类：

```kt
    class MyApplicationTestRunner : AndroidJUnitRunner() {
        @Throws(Exception::class)
        override fun newApplication(
            cl: ClassLoader?,
            className: String?,
            context: Context?
        ): Application? {
            return super.newApplication(cl,           TestMyApplication::class.java.name, context)
        }
    }
    ```

1.  将新的测试运行器添加到 Gradle 配置中：

```kt
    android {
        ...
        defaultConfig {        
            ...
            testInstrumentationRunner            "com.android.testable.myapplication            .MyApplicationTestRunner"
        }
    }
    ```

现在运行测试，一切应该与*图 9.8*类似地通过：

![图 9.8：练习 9.03 的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_08.jpg)

图 9.8：练习 9.03 的输出

这种类型的练习展示了如何避免测试中的随机性，并提供具体和可重复的输入，使我们的测试更加可靠。类似的方法也适用于依赖注入框架，可以在测试套件中替换整个模块，以确保测试的可靠性。最常替换的一种是 API 通信。这种方法解决的另一个问题是等待时间的减少。如果这种情况在你的测试中重复出现，那么它们的执行时间会因此增加。

# 测试驱动开发

假设你的任务是构建一个显示带有加、减、乘、除选项的计算器的活动。你还必须为你的实现编写测试。通常情况下，你会构建你的 UI 和你的活动以及一个单独的`Calculator`类。然后，你会为`Calculator`类编写单元测试，然后为你的活动类编写单元测试。

在`Calculator`测试下。在这里，你还需要在`Calculator`类中创建必要的方法，以避免编译时错误。

如果你在这个阶段运行你的测试，它们会失败。这将迫使你实现你的代码，直到测试通过。一旦你的`Calculator`测试通过，你就可以把你的计算器连接到你的 UI，直到你的 UI 测试通过。虽然这看起来像是一个违反直觉的方法，一旦掌握了这个过程，它能解决两个问题：

+   因为你会确保你的代码是可测试的，所以写代码的时间会减少，并且你只需要写必要数量的代码来使测试通过。

+   由于开发者能够分析不同的结果，会减少引入的 bug。

请看下图，显示了 TDD 循环：

![图 9.9：TDD 循环](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_09.jpg)

图 9.9：TDD 循环

在前述图中，我们可以看到 TDD 过程中的开发循环。你应该从测试失败的点开始。实现变更以使测试通过。当你更新或添加新特性时，你可以重复这个过程。

回到我们的阶乘例子，我们开始时有一个没有涵盖所有场景的阶乘函数，不得不在添加新测试时不断更新函数。TDD 就是以这个想法为基础的。你从一个空函数开始。你开始定义你的测试场景：成功的条件是什么？最小值是多少？最大值是多少？有没有例外情况？它们是什么？这些问题可以帮助开发者定义他们的测试案例。然后，这些案例可以被书写。接下来我们看看这如何通过下一个练习来实际做到。

## 练习 9.04：使用 TDD 计算数字之和

编写一个函数，该函数将以整数*n*作为输入，并返回 1 到*n*的数字之和。这个函数应该采用 TDD 方法编写，并且应满足以下标准：

+   对于*n<=0*，该函数将返回值`-1`。

+   该函数应能返回`Int.MAX_VALUE`的正确值。

+   该函数应该快速，即使对于`Int.MAX_VALUE`也是如此。

注

在整个练习过程中，不会显示导入语句。要查看完整的代码文件，请参考[`packt.live/3a0jJd9`](http://packt.live/3a0jJd9)：

执行以下步骤完成此练习：

1.  确保以下库已添加到`app/build.gradle`中：

```kt
    testImplementation 'junit:junit:4.13.1'
    ```

1.  创建一个具有`sum`方法的`Adder`类，该方法将返回`0`，以满足编译器：

```kt
    class Adder {
        fun sum(n: Int): Int = 0
    }
    ```

1.  在测试目录中创建一个`AdderTest`类并定义我们的测试用例。我们将有以下测试用例：*n=1*、*n=2*、*n=0*、*n=-1*、*n=10*、*n=20* 和 *n=Int.MAX_VALUE*。我们可以将成功场景分为一个方法，不成功的场景分为另一个方法：

```kt
    class AdderTest {
        private val adder = Adder()
        @Test
        fun sumSuccess() {
            assertEquals(1, adder.sum(1))
            assertEquals(3, adder.sum(2))
            assertEquals(55, adder.sum(10))
            assertEquals(210, adder.sum(20))
            assertEquals(2305843008139952128L, adder.sum(Int.MAX_VALUE))
        }
        @Test
        fun sumError(){
            assertEquals(-1, adder.sum(0))
            assertEquals(-1, adder.sum(-1))
        }
    }
    ```

1.  如果我们对`AdderTest`类运行测试，我们会看到类似以下图表的输出，意味着所有测试都失败了：![图 9.10：练习 9.04 的初始测试状态](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_10.jpg)

图 9.10：练习 9.04 的初始测试状态

1.  让我们先通过在循环中实现从 1 到*n*的求和来处理成功场景：

```kt
    class Adder {
        fun sum(n: Int): Long {
            var result = 0L
            for (i in 1..n) {
                result += i
            }
            return result
        }
    }
    ```

1.  如果我们现在运行测试，你会发现其中一个会通过，另一个会失败，类似于以下图表：![图 9.11：解决练习 9.04 成功场景后的测试状态](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_09_11.jpg)

图 9.11：解决练习 9.04 成功场景后的测试状态

1.  如果我们查看执行成功测试所需的时间，似乎有点长。当一个项目中存在成千上万的单元测试时，这些时间就会相加起来。我们现在可以通过应用*n(n+1)/2*的公式来优化我们的代码以解决这个问题：

```kt
    class Adder {
        fun sum(n: Int): Long {
            return (n * (n.toLong() + 1)) / 2
        }
    }
    ```

现在运行测试将显著减少速度到几毫秒。

1.  现在，让我们专注于解决我们的失败场景。我们可以通过为*n*小于或等于`0`时添加一个条件来做到这一点：

```kt
    class Adder {
        fun sum(n: Int): Long {
            return if (n > 0) (n * (n.toLong() + 1)) / 2 else -1
        }
    }
    ```

1.  如果现在运行测试，我们应该看到它们全部通过，类似于以下图：![图 9.12：练习 9.04 的通过测试

]（img/B15216_09_12.jpg）

图 9.12：练习 9.04 的通过测试

在这个练习中，我们已经将 TDD 的概念应用到了一个非常小的示例中，以演示如何使用该技术。我们已经观察到，从骨架代码开始，我们可以创建一套测试来验证我们的条件，通过不断运行测试，我们改进了代码，直到所有测试都通过的地步。您可能已经注意到，这个概念并不直观。一些开发人员很难定义骨架代码应该有多大，才能开始创建测试用例，而其他人则出于习惯，专注于先编写代码，然后再开发测试。无论哪种情况，开发人员都需要通过该技术进行大量练习，直到熟练掌握为止。

## Activity 9.01：使用 TDD 开发

使用 TDD 方法，开发一个包含三个活动并按以下方式工作的应用程序：

+   在活动 1 中，您将显示一个数字`EditText`元素和一个按钮。单击按钮后，将`EditText`中的数字传递给活动 2。

+   Activity 2 将异步生成项目列表。项目的数量将由从活动 1 传递的数字表示。您可以使用`Timer`类，延迟 1 秒。列表中的每个项目将显示文本`Item x`。 `x`是列表中的位置。单击项目时，应将单击的项目传递给活动 3。

+   活动 3 将显示文本`You clicked y`。 `y`是用户单击的项目的文本。

应用程序将具有以下测试：

+   使用 Mockito 和`mockito-kotlin`进行单元测试，注释为`@SmallTest`

+   使用 Robolectric 和 Espresso 进行集成测试，并用`@MediumTest`进行注释

+   使用 Espresso 进行 UI 测试，并用`@LargeTest`进行注释，使用 Robot 模式

从命令行运行测试命令。

为了完成此活动，您需要采取以下步骤：

1.  您需要 Android Studio 4.1.1 或更高版本，以及 Kotlin 1.4.21 或更高版本的 Parcelize Kotlin 插件

1.  为每个活动和其 UI 创建三个活动。

1.  在`androidTest`文件夹中，为每个活动创建三个机器人：

+   Robot 1 将包含与`EditText`和按钮的交互。

+   Robot 2 将断言屏幕上的项目数量和与列表中项目的交互。

+   Robot 3 将断言`TextView`中显示的文本。

1.  创建一个仪器测试类，其中将使用前述机器人进行一个测试方法。

1.  创建一个`Application`类，其中将保存将进行单元测试的所有类的实例。

1.  创建三个表示集成测试的类，每个类对应一个活动。每个集成测试类将包含一个测试方法，用于交互和数据加载。每个集成测试将断言在活动之间传递的意图。

1.  创建一个类，用于提供 UI 所需的文本。它将引用一个`Context`对象，并包含两个方法，用于为 UI 提供文本，将返回一个空字符串。

1.  创建前述类的测试，在其中测试两种方法。

1.  实现类以使前述测试通过。

1.  创建一个类，负责在`Activity2`中加载列表，并提供一个加载的空方法。该类将引用计时器和空闲资源。在这里，您还应该创建一个数据类，用于表示`RecyclerView`的模型。

1.  为前述类创建一个单元测试。

1.  创建前述类的实现并运行单元测试，直到它们通过。

1.  在`Application`类中，实例化已进行单元测试的类，并开始在您的活动中使用它们。直到您的集成测试通过为止。

1.  提供`IntegrationTestApplication`，它将返回负责加载的类的新实现。这是为了避免使您的活动 2 的集成测试等待加载完成。

1.  提供`UiTestApplication`，它将再次减少模型的加载时间，并将空闲资源连接到 Espresso。实现剩下的工作以使 UI 测试通过。

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 总结

在本章中，我们看了不同类型的测试和可用于实施这些测试的框架。我们还看了测试环境以及如何为每个环境构建结构，以及如何将代码结构化为可以单独进行单元测试的多个组件。我们分析了测试代码的不同方式，我们应该如何进行测试，以及通过查看不同的测试结果，我们如何改进我们的代码。通过 TDD，我们了解到通过从测试开始，我们可以更快地编写代码，并确保它更少出错。活动是所有这些概念汇集在一起构建一个简单的 Android 应用程序的地方，我们可以观察到，通过添加测试，开发时间增加了，但这在长期内通过消除在修改代码时出现的可能错误而得到了回报。

我们学习过的框架是一些最常见的框架，但还有其他一些建立在这些框架之上并被开发人员在他们的项目中使用的框架，包括 mockk（一种为 Kotlin 设计的模拟库，充分利用了语言的许多特性），Barista（建立在 Espresso 之上，简化了 UI 测试的语法），屏幕截图测试（对 UI 测试进行截图并进行比较以验证是否引入了错误），UIAutomator 和 monkeyrunner（执行 UI 测试而无需访问应用程序代码，但是建立在其之上），Spoon（允许在多个模拟器上并行执行 UI 测试以减少测试时间），以及 Firebase 测试实验室（允许在云中执行测试）。

将这里介绍的所有概念视为适用于软件工程世界中的两个过程的构建块：自动化和持续集成。自动化将开发人员手中的冗余和重复工作交给机器。与其让一组质量保证人员测试您的应用程序以确保满足要求，不如通过各种测试和测试用例指示机器来测试应用程序，只需一个人审查测试结果。持续集成建立在自动化的概念之上，以便在您提交代码进行其他开发人员审查时立即验证代码。具有持续集成的项目将按以下方式设置：开发人员将工作提交到 GitHub 等源代码存储库进行审查。

然后，云中的一台机器将开始执行整个项目的测试，确保没有任何问题，开发人员可以继续进行新的任务。如果测试通过，那么其他开发人员可以审查代码，当正确时，可以合并并在云中创建新的构建并分发给团队的其他成员和测试人员。在初始开发人员可以安全地进行其他工作的同时进行所有这些操作。如果在过程中出现任何失败，那么他们可以暂停新任务并解决工作中的任何问题。然后可以将持续集成过程扩展为持续交付，在准备提交到 Google Play 时可以设置类似的自动化，几乎完全由机器处理，开发人员只需进行少量参与。在接下来的章节中，您将了解如何在构建使用设备存储功能并连接到云以请求数据的更复杂的应用程序时组织代码。每个组件都可以进行单独的单元测试，并且可以应用集成测试来断言多个组件的成功集成。
