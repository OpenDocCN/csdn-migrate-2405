# 精通 Kotlin 安卓开发（四）

> 原文：[`zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5`](https://zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：消息

在本章中，我们将使用 Android 广播，并将其用作接收和发送消息的机制。我们将分步理解它。首先，我们将解释底层机制以及如何使用 Android 广播消息。然后，我们将监听一些最常见的消息。因为仅仅监听是不够的，我们将创建新的消息并进行广播。最后，我们将了解启动、关闭和网络广播消息，以便我们的应用程序意识到这一重要的系统事件。

在本章中，我们将涵盖以下主题：

+   Android 广播

+   监听广播

+   创建广播

+   监听网络事件

# 理解 Android 广播

Android 应用程序可以发送或接收消息。消息可以是系统相关事件，也可以是我们定义的自定义事件。感兴趣的各方通过定义适当的意图过滤器和广播接收器来注册特定的消息。当广播消息时，所有感兴趣的各方都会收到通知。重要的是要注意，一旦你订阅了广播消息（特别是从`Activity`类），你必须在某个时候取消订阅。我们什么时候可以使用广播消息？我们在应用程序需要跨应用程序的消息系统时使用广播消息。例如，想象一下你在后台启动了一个长时间运行的进程。在某个时候，你想通知多个上下文处理结果。广播消息是这个问题的完美解决方案。

# 系统广播

系统广播是在发生各种系统事件时由 Android 系统发送的广播。我们发送和最终接收的每条消息都包装在包含有关特定事件信息的`Intent`类中。每个`Intent`必须设置适当的操作。例如--`android.intent.action.ACTION_POWER_CONNECTED`。有关事件的信息用捆绑的额外数据表示。例如，我们可能捆绑了一个额外的字符串字段，表示与我们感兴趣的事件相关的特定数据。让我们考虑一个充电和电池信息的例子。每当电池状态发生变化时，感兴趣的各方将收到通知，并接收包含电池电量信息的广播消息：

```kt
    val intentFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED) 
    val batteryStatus = registerReceiver(null, intentFilter) 

    val status = batteryStatus.getIntExtra(BatteryManager.
      EXTRA_STATUS, -1) 

    val isCharging = 
                status == BatteryManager.BATTERY_STATUS_CHARGING || 
                status == BatteryManager.BATTERY_STATUS_FULL 

    val chargePlug =    batteryStatus.getIntExtra(BatteryManager.
      EXTRA_PLUGGED, -1) 
    val usbCharge = chargePlug == BatteryManager.
      BATTERY_PLUGGED_USB 
    val acCharge = chargePlug == BatteryManager.BATTERY_PLUGGED_AC
```

在这个例子中，我们注册了电池信息的意图过滤器。然而，我们没有传递广播接收器的实例。为什么？因为电池数据是粘性的。**粘性意图**是在广播执行后一段时间内保持存在的意图。注册到这些数据将立即返回包含最新数据的意图。我们也可以传递广播接收器的实例。让我们来做一下：

```kt
    val receiver = object : BroadcastReceiver() { 
      override fun onReceive(p0: Context?, batteryStatus: Intent?) { 
      val status = batteryStatus?.getIntExtra
      (BatteryManager.EXTRA_STATUS, -1) 
                 val isCharging = 
                        status == 
                        BatteryManager.BATTERY_STATUS_CHARGING || 
                        status == BatteryManager.BATTERY_STATUS_FULL 
                        val chargePlug = batteryStatus?.getIntExtra
                       (BatteryManager.EXTRA_PLUGGED, -1) 
                        val usbCharge = chargePlug ==
                       BatteryManager.BATTERY_PLUGGED_USB 
                       val acCharge = chargePlug == 
                       BatteryManager.BATTERY_PLUGGED_AC 
        } 
    } 

    val intentFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED) 
    registerReceiver(receiver, intentFilter)
```

每当电池信息发生变化时，接收器将执行我们在其实现中定义的代码；我们也可以在 Android 清单中定义我们的接收器：

```kt
    <receiver android:name=".OurPowerReceiver"> 
      <intent-filter> 
        <action android:name="android.intent.action.
        ACTION_POWER_CONNECTED"/> 
        <action android:name="android.intent.action.
        ACTION_POWER_DISCONNECTED"/> 
      </intent-filter> 
    </receiver>
```

# 监听广播

如前面的例子所示，我们可以以以下两种方式之一接收广播：

+   通过 Android 清单注册广播接收器

+   使用`registerBroadcast()`方法在上下文中注册广播

通过清单声明需要以下内容：

+   带有`android:name`和`android:exported`参数的`<receiver>`元素。

+   接收器必须包含我们订阅的操作的`intent`过滤器。看看下面的例子：

```kt
        <receiver android:name=".OurBootReceiver"
          android:exported="true"> 
          <intent-filter> 
            <action android:name=
            "android.intent.action.BOOT_COMPLETED"/> 
            ... 
            <action android:name="..."/> 
            <action android:name="..."/> 
            <action android:name="..."/> 

         </intent-filter> 

       </receiver> 
```

如你所见，`name`属性代表我们广播接收器类的名称。导出意味着应用程序可以或不能接收来自接收器应用程序外部的消息。

如果你子类化`BroadcastReceiver`，它应该像这个例子一样：

```kt
     val receiver = object : BroadcastReceiver() { 
        override fun onReceive(ctx: Context?, intent: Intent?) { 
            // Handle your received code. 

        } 
    }
```

注意，在`onReceive()`方法实现中执行的操作不应该花费太多时间。否则会发生 ANR！

# 从上下文注册

现在我们将向您展示一个从 Android 上下文注册广播接收器的示例。要注册接收器，你需要它的一个实例。假设我们的实例是`myReceiver`：

```kt
    val myReceiver = object : BroadcastReceiver(){ 

      ... 

     }We need intent filter prepared: 
     val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
     registerReceiver(myReceiver, filter)
```

这个例子将注册一个接收者，用于监听连接信息。由于此接收者是从上下文中注册的，只要我们注册的上下文有效，它就是有效的。您还可以使用`LocalBroadcastManager`类。`LocalBroadcastManager`的目的是注册并向您进程中的本地对象发送意图的广播。这是例子：

```kt
    LocalBroadcastManager 
      .getInstance(applicationContext) 
      .registerReceiver(myReceiver, intentFilter)
```

要取消注册，请执行以下代码片段：

```kt
    LocalBroadcastManager 
      .getInstance(applicationContext) 
      .unregisterReceiver(myReceiver)
```

对于上下文订阅的接收者，重点要注意取消注册。例如，如果我们在活动的`onCreate()`方法中注册接收者，我们必须在`onDestroy()`方法中取消注册。如果我们不这样做，就会出现接收者泄漏！同样，如果我们在活动的`onResume()`中注册，我们必须在`onPause()`中取消注册。如果我们不这样做，就会多次注册！

# 接收者执行

我们在`onReceive()`实现中执行的代码被视为前台进程。广播接收器在我们从该方法返回之前是活动的。系统将始终运行您在实现中定义的代码，除非发生极端的内存压力。正如我们提到的，您应该只执行短操作！否则，可能会发生 ANR！当接收到消息时执行长时间运行的操作的一个很好的例子是启动`AsyncTask`并在那里执行所有工作。接下来，我们将向您展示一个演示这一点的例子：

```kt
     class AsyncReceiver : BroadcastReceiver() { 
       override fun onReceive(p0: Context?, p1: Intent?) { 
         val pending = goAsync() 
         val async = object : AsyncTask<Unit, Unit, Unit>() { 
           override fun doInBackground(vararg p0: Unit?) { 
             // Do some intensive work here... 
             pending.finish() 
           } 
       } 
       async.execute() 
      }
    } 
```

在这个例子中，我们介绍了`goAsync()`方法的使用。它是做什么的？该方法返回一个`PendingResult`类型的对象，表示调用`API`方法的待定结果。Android 系统认为接收者在调用此实例的`finish()`方法之前是活动的。使用这种机制，可以在广播接收器中进行异步处理。在完成繁重的工作后，我们调用`finish()`来指示 Android 系统可以回收此组件。

# 发送广播

Android 有以下三种发送广播消息的方式：

+   使用`sendOrderedBroadcast(Intent, String)`方法一次向一个接收者发送消息。由于接收者按顺序执行，可以将结果传播给下一个接收者。此外，还可以中止广播，使其不会传递给其他接收者。我们可以控制接收者执行的顺序。我们可以使用匹配意图过滤器的`android:priority`属性来设置优先级。

+   使用`sendBroadcast(Intent)`方法向所有接收者发送广播消息。发送是无序的。

+   使用`LocalBroadcastManager.sendBroadcast(Intent)`方法向与发送方相同应用程序中的接收者发送广播。

让我们看一个向所有感兴趣的方发送广播消息的例子：

```kt
    val intent = Intent() 
    intent.action = "com.journaler.broadcast.TODO_CREATED" 
    intent.putExtra("title", "Go, buy some lunch.") 
    intent.putExtra("message", "For lunch we have chicken.")
    sendBroadcast(intent)
```

我们创建了一个包含有关我们创建的`note`（标题和消息）的额外数据的广播消息。所有感兴趣的方都需要一个适当的`IntentFilter`实例来执行操作：

```kt
    com.journaler.broadcast.TODO_CREATED
```

不要混淆启动活动和发送广播消息。`Intent`类只是用作我们信息的包装器。这两个操作完全不同！您可以使用本地广播机制来实现相同的功能：

```kt
    val ctx = ... 
    val broadcastManager = LocalBroadcastManager.getInstance(ctx) 
    val intent = Intent() 
    intent.action = "com.journaler.broadcast.TODO_CREATED" 
    intent.putExtra("title", "Go, buy some lunch.") 
    intent.putExtra("message", "For lunch we have chicken.") 
    broadcastManager.sendBroadcast(intent)
```

现在，当我们向您展示了广播消息的最重要方面后，我们将继续扩展我们的应用程序。Journaler 将发送和接收包含数据的自定义广播消息，并与系统广播进行交互，例如系统启动、关闭和网络。

# 创建自己的广播消息

正如你可能记得的，我们对`NoteActivity`类进行了代码重构。让我们展示我们在重要部分的最后状态，以便进行进一步的演示：

```kt
     class NoteActivity : ItemActivity() { 
       ... 
       private val locationListener = object : LocationListener { 
         override fun onLocationChanged(p0: Location?) { 
           p0?.let { 
                LocationProvider.unsubscribe(this) 
                location = p0 
                val title = getNoteTitle() 
                val content = getNoteContent() 
                note = Note(title, content, p0) 

                // Switching to intent service. 
                val dbIntent = Intent(this@NoteActivity,
                DatabaseService::class.java) 
                dbIntent.putExtra(DatabaseService.EXTRA_ENTRY, note) 
                dbIntent.putExtra(DatabaseService.EXTRA_OPERATION,
                MODE.CREATE.mode) 
                startService(dbIntent) 
                sendMessage(true) 
            } 
        } 

        override fun onStatusChanged(p0: String?, p1: Int, p2: Bundle?)
        {} 
        override fun onProviderEnabled(p0: String?) {} 
        override fun onProviderDisabled(p0: String?) {} 
      } 
      ... 
      private fun updateNote() { 
        if (note == null) { 
            if (!TextUtils.isEmpty(getNoteTitle()) &&
             !TextUtils.isEmpty(getNoteContent())) { 
               LocationProvider.subscribe(locationListener) 
            } 
        } else { 
            note?.title = getNoteTitle() 
            note?.message = getNoteContent() 

            // Switching to intent service. 
            val dbIntent = Intent(this@NoteActivity,
            DatabaseService::class.java) 
            dbIntent.putExtra(DatabaseService.EXTRA_ENTRY, note) 
            dbIntent.putExtra(DatabaseService.EXTRA_OPERATION,
            MODE.EDIT.mode) 
            startService(dbIntent) 
            sendMessage(true) 
        } 
      } 
      ... 
    }
```

如果您再次查看这个，您会注意到我们在执行时向我们的服务发送了`intent`，但由于我们没有得到返回值，我们只是用布尔值`true`作为其参数执行了`sendMessage()`方法。在这里，我们期望一个代表 CRUD 操作结果的值，即成功或失败。我们将使用广播消息将我们的服务与`NoteActivity`连接起来。每次插入或更新`note`广播时，都会触发一个消息。我们在`NoteActivity`中定义的监听器将对此消息做出响应并触发`sendMessage()`方法。让我们更新我们的代码！打开`Crud`接口并使用包含操作和 CRUD 操作结果常量的`companion`对象进行扩展：

```kt
    interface Crud<T> { 
      companion object { 
        val BROADCAST_ACTION = "com.journaler.broadcast.crud" 
        val BROADCAST_EXTRAS_KEY_CRUD_OPERATION_RESULT = "crud_result" 
      } 
       ... 
    }
```

现在，打开`DatabaseService`并扩展它，负责在执行 CRUD 操作时发送广播消息的方法：

```kt
     class DatabaseService : IntentService("DatabaseService") { 
       ... 
       override fun onHandleIntent(p0: Intent?) { 
          p0?.let { 
            val note = p0.getParcelableExtra<Note>(EXTRA_ENTRY) 
            note?.let { 
                val operation = p0.getIntExtra(EXTRA_OPERATION, -1) 
                when (operation) { 
                    MODE.CREATE.mode -> { 
                        val result = Db.insert(note) 
                        if (result) { 
                            Log.i(tag, "Note inserted.") 
                        } else { 
                            Log.e(tag, "Note not inserted.") 
                        } 
                        broadcastResult(result) 
                    } 
                    MODE.EDIT.mode -> { 
                        val result = Db.update(note) 
                        if (result) { 
                            Log.i(tag, "Note updated.") 
                        } else { 
                            Log.e(tag, "Note not updated.") 
                        } 
                        broadcastResult(result) 
                    } 
                    else -> { 
                        Log.w(tag, "Unknown mode [ $operation ]") 
                    } 
                 } 
             } 
           } 
        } 
        ... 
        private fun broadcastResult(result: Boolean) { 
          val intent = Intent() 
          intent.putExtra( 
                Crud.BROADCAST_EXTRAS_KEY_CRUD_OPERATION_RESULT, 
                if (result) { 
                    1 
                } else { 
                    0 
                } 
          ) 
        } }
```

我们引入了一个新方法。其他一切都一样。我们将获取 CRUD 操作结果并将其作为消息广播。`NoteActivity`将监听它：

```kt
   class NoteActivity : ItemActivity() { 
     ... 
     private val crudOperationListener = object : BroadcastReceiver() { 
        override fun onReceive(ctx: Context?, intent: Intent?) { 
            intent?.let { 
                val crudResultValue =
                intent.getIntExtra(MODE.EXTRAS_KEY, 0) 
                sendMessage(crudResultValue == 1) 
            } 
        } 
      } 
      ... 
      override fun onCreate(savedInstanceState: Bundle?) { 
        .... 
        registerReceiver(crudOperationListener, intentFiler) 
      } 

      override fun onDestroy() { 
        unregisterReceiver(crudOperationListener) 
        super.onDestroy() 
      } 
      ... 
      private fun sendMessage(result: Boolean) { 
         Log.v(tag, "Crud operation result [ $result ]") 
         val msg = handler?.obtainMessage() 
         if (result) { 
            msg?.arg1 = 1 
         } else { 
            msg?.arg1 = 0 
         } 
         handler?.sendMessage(msg) 
     } }
```

这很简单！我们重新连接了原始的`sendMessage()`方法与 CRUD 操作结果。在接下来的章节中，我们将考虑应用程序可以通过监听启动、关机和网络广播消息来进行一些重大改进。

# 使用启动和关闭广播

有时，服务在应用程序启动时运行至关重要。有时，在终止之前进行一些清理工作也很重要。在下面的示例中，我们将扩展 Journaler 应用程序以监听这些广播消息并进行一些工作。我们要做的第一件事是创建两个扩展`BroadcastReceiver`类的类：

+   `BootReceiver`：这是处理系统启动事件的

+   `ShutdownReceiver`：这是处理系统关机事件的

在`manifest`文件中注册它们如下：

```kt
    <manifest  
     ... 
    > 
    ... 
    <receiver 
        android:name=".receiver.BootReceiver" 
        android:enabled="true" 
        android:exported="false"> 
        <intent-filter> 
          <action android:name=
           "android.intent.action.BOOT_COMPLETED" /> 
        </intent-filter> 

        <intent-filter> 
          <action android:name=
          "android.intent.action.PACKAGE_REPLACED" /> 
          data android:scheme="package" /> 
        </intent-filter> 

        <intent-filter> 
          <action android:name=
          "android.intent.action.PACKAGE_ADDED" /> 
          <data android:scheme="package" /> 
        </intent-filter> 
     </receiver> 

    <receiver android:name=".receiver.ShutdownReceiver"> 

      <intent-filter> 
        <action android:name=
        "android.intent.action.ACTION_SHUTDOWN" /> 
        <action android:name=
        "android.intent.action.QUICKBOOT_POWEROFF" /> 
      </intent-filter> 
    </receiver> 
     ...
    </manifest> 
```

`BootReceiver`类将在启动或替换应用程序时触发。关闭将在关闭设备时触发。让我们创建适当的实现。打开`BootReceiver`类并定义如下：

```kt
     package com.journaler.receiver 

     import android.content.BroadcastReceiver 
     import android.content.Context 
     import android.content.Intent 
     import android.util.Log 

     class BootReceiver : BroadcastReceiver() { 

       val tag = "Boot receiver" 

       override fun onReceive(p0: Context?, p1: Intent?) { 
         Log.i(tag, "Boot completed.") 
         // Perform your on boot stuff here. 
       } 

     } 
```

如您所见，我们为这两个类定义了`receiver`包。对于`ShutdownReceiver`，请像这样定义类：

```kt
    package com.journaler.receiver 

    import android.content.BroadcastReceiver 
    import android.content.Context 
    import android.content.Intent 
    import android.util.Log 

    class ShutdownReceiver : BroadcastReceiver() { 

      val tag = "Shutdown receiver" 

      override fun onReceive(p0: Context?, p1: Intent?) { 
        Log.i(tag, "Shutting down.") 
        // Perform your on cleanup stuff here.   
      } }
```

为了使其工作，我们需要进行一次更改；否则，应用程序将崩溃。从`Application`类中启动`main`服务移动到主活动`onCreate()`方法中。这是`Journaler`类的第一个更新：

```kt
    class Journaler : Application() { 
      ... 
      override fun onCreate() { // We removed start service method
        execution. 
        super.onCreate() 
        ctx = applicationContext 
        Log.v(tag, "[ ON CREATE ]") 
     } 
     // We removed startService() method implementation. 
     ... 
    }
```

然后通过在`onCreate()`方法的末尾添加行来扩展`MainActivity`类：

```kt
    class MainActivity : BaseActivity() { 
      ... 
      override fun onCreate(savedInstanceState: Bundle?) { 
        ... 
        val serviceIntent = Intent(this, MainService::class.java) 
        startService(serviceIntent) 
     } 
    ... } }
```

构建并运行您的应用程序。首先关闭手机，然后再次开机。过滤您的 Logcat，使其仅显示应用程序的日志。您应该有以下输出：

```kt
... I/Shutdown receiver: Shutting down. 
... I/Boot receiver: Boot completed.
```

请记住，有时需要超过两分钟才能接收到启动事件！

# 监听网络事件

我们想要的最后一个改进是在建立连接时使我们的应用程序能够执行同步。在相同的`NetworkReceiver`包中创建一个名为的新类。确保您有以下实现：

```kt
    class NetworkReceiver : BroadcastReceiver() {
      private val tag = "Network receiver"
      private var service: MainService? = null

      private val serviceConnection = object : ServiceConnection { 
        override fun onServiceDisconnected(p0: ComponentName?) { 
          service = null 
        } 

        override fun onServiceConnected(p0: ComponentName?, binder:
        IBinder?) { 
            if (binder is MainService.MainServiceBinder) { 
                service = binder.getService() 
                service?.synchronize() 
            } 
        } 
       } 

       override fun onReceive(context: Context?, p1: Intent?) { 
       context?.let { 

            val cm = context.getSystemService
           (Context.CONNECTIVITY_SERVICE) as ConnectivityManager 

            val activeNetwork = cm.activeNetworkInfo 
            val isConnected = activeNetwork != null &&
            activeNetwork.isConnectedOrConnecting 
            if (isConnected) { 
                Log.v(tag, "Connectivity [ AVAILABLE ]") 
                if (service == null) { 
                    val intent = Intent(context,
                    MainService::class.java) 
                    context.bindService( 
                        intent, serviceConnection,
                        android.content.Context.BIND_AUTO_CREATE 
                    ) 
                } else { 
                    service?.synchronize() 
                } 
            } else { 
                Log.w(tag, "Connectivity [ UNAVAILABLE ]") 
                context.unbindService(serviceConnection) 
            } 
          } 
        } 
    }
```

当发生连接事件时，此接收器将接收消息。每当我们有上下文和连接时，我们将绑定到服务并触发同步。不要担心频繁的同步触发，因为在接下来的章节中，我们将在同步方法的实现中保护自己免受它的影响。通过更新 Journaler 应用程序类来注册您的监听器如下：

```kt
     class Journaler : Application() { 
       ... 
       override fun onCreate() { 
          super.onCreate() 
          ctx = applicationContext 
          Log.v(tag, "[ ON CREATE ]") 
          val filter =  
          IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION) 
          registerReceiver(networkReceiver, filter) 
      } 
      ... 
    } 
```

构建并运行您的应用程序。关闭您的连接（Wi-Fi、移动数据）然后再次打开。观察以下 Logcat 输出：

```kt
... V/Network receiver: Connectivity [ AVAILABLE ] 
... V/Network receiver: Connectivity [ AVAILABLE ] 
... V/Network receiver: Connectivity [ AVAILABLE ] 
... W/Network receiver: Connectivity [ UNAVAILABLE ] 
... V/Network receiver: Connectivity [ AVAILABLE ] 
... V/Network receiver: Connectivity [ AVAILABLE ] 
... V/Network receiver: Connectivity [ AVAILABLE ] 
```

# 总结

在本章中，我们学习了如何使用广播消息。我们还学习了如何监听系统广播消息以及我们自己创建的广播消息。Journaler 应用程序得到了显著改进，变得更加灵活。我们不会止步于此，而是将通过学习新知识和扩展我们的代码来继续在 Android 框架中取得进展。


# 第十二章：后端和 API

在本章中，我们将把我们的应用程序连接到远程后端实例。我们创建的所有数据都将与后端同步。对于 API 调用，我们将使用 Retrofit。Retrofit 是 Android 平台上最常用的 HTTP 客户端。我们将逐步指导您通过常见的实践，以便您可以轻松地连接和实现将来在任何应用程序中连接到后端。

这一章是本书中迄今为止最长的一章，在这里，我们将涵盖许多重要的内容，如以下主题：

+   使用 data 类

+   Retrofit

+   Gson 与 Kotson 库

+   内容提供程序

+   内容加载器

+   Android 适配器

+   数据绑定

+   使用列表和网格

仔细阅读本章，并享受玩耍您的应用程序。

# 识别使用的实体

在我们同步任何内容之前，我们必须确定我们将要同步的内容。这个问题的答案是显而易见的，但我们无论如何都会回顾一下我们的实体列表。我们计划同步的主要实体有两个：

+   `Note`实体

+   `Todo`实体

它们具有以下属性：

+   共同属性：

+   `title`：`String`

+   `message`：`String`

+   `location`：`Location`（将被序列化）

请注意，目前我们在数据库中用纬度和经度表示位置。我们将把这个改为`Text`类型，因为我们将引入 Gson 和 Kotson 进行序列化/反序列化！

+   Todo 特定属性如下：

+   `scheduledFor`：`Long`

再次打开您的类并查看它们。

# 使用 data 类

在 Kotlin 中，建议使用`data`类作为实体的表示。在我们的情况下，我们没有使用`data`类，因为我们扩展了一个包含`Note`和`Todo`类之间共享属性的通用类。

我们建议使用`data`类，因为它可以显著简化您的工作流程，特别是如果您在后端通信中使用这些实体。

我们经常需要只有一个目的的类--保存数据。使用`data`类的好处是，通常与其目的一起使用的一些功能会自动提供。您可能已经知道如何定义`data`类，您必须这样做：

```kt
   data class Entity(val param1: String, val param2: String) 
```

对于`data`类，编译器会自动为您提供以下内容：

+   `equals()`和`hashCode()`方法

+   `toString()`方法以人类可读的形式，

`Entity(param1=Something, param2=Something)`

+   用于克隆的`copy()`方法

所有`data`类必须满足以下要求：

+   主构造函数需要至少有一个参数

+   所有主构造函数参数都需要标记为`val`或`var`

+   `data`类不能是`abstract`，`open`，`sealed`或`inner`

让我们介绍一些`data`类！由于我们计划使用远程后端实例，这将需要一些身份验证。我们将为身份验证过程中传递的数据创建新的实体（`data`类），以及身份验证结果。创建一个名为`api`的新包。然后，创建一个名为`UserLoginRequest`的新的`data`类，如下所示：

```kt
     package com.journaler.api 

     data class UserLoginRequest( 
        val username: String, 
        val password: String 
     )  
```

`UserLoginRequest`类将包含我们的身份验证凭据。API 调用将返回一个 JSON，该 JSON 将被反序列化为`JournalerApiToken`的`data`类，如下所示：

```kt
    package com.journaler.api 
    import com.google.gson.annotations.SerializedName 

    data class JournalerApiToken( 
        @SerializedName("id_token") val token: String, 
        val expires: Long 
    ) 
```

注意我们使用注解告诉 Gson，token 字段将从 JSON 中的`id_token`字段获取。

总之--始终考虑使用`data`类！特别是如果它们所代表的数据将用于保存数据库和后端信息。

# 将数据模型连接到数据库

如果您像 Journaler 应用程序一样拥有一个在数据库中保存数据并计划将其与远程后端实例同步的场景，首先创建一个将存储数据的持久层可能是一个好主意。将数据持久化到本地文件系统数据库可以防止数据丢失，特别是如果数据量较大！

所以，我们做了什么？我们创建了一个持久化机制，将所有数据存储到 SQLite 数据库中。然后，在本章中，我们将介绍后端通信机制。因为我们不知道我们的 API 调用是否会失败，或者后端实例是否可用，所以我们将数据持久化。如果我们只将数据保存在设备内存中，如果同步的 API 调用失败并且我们的应用程序崩溃，我们可能会丢失这些数据。假设 API 调用失败并且应用程序崩溃，但我们的数据已持久化，我们可以重试同步。数据仍然存在！

# Retrofit 介绍

正如我们已经提到的，Retrofit 是一个开源库。它是当今最流行的 Android HTTP 客户端。因此，我们将向您介绍 Retrofit 的基础知识，并演示如何使用它。我们将涵盖的版本是 2.3.0。我们将为您提供如何使用它的逐步指导。

首先，Retrofit 也依赖于一些库。我们将与 Okhttp 一起使用。Okhttp 是由开发 Retrofit 的同一团队开发的 HTTP/HTTP2 客户端。在开始之前，我们将把依赖项放入我们的`build.gradle`配置中，如下所示：

```kt
    apply plugin: "com.android.application" 
    apply plugin: "kotlin-android" 
    apply plugin: "kotlin-android-extensions" 
    ... 
    dependencies { 
      ... 
      compile 'com.squareup.retrofit2:retrofit:2.3.0' 
      compile 'com.squareup.retrofit2:converter-gson:2.0.2' 
      compile 'com.squareup.okhttp3:okhttp:3.9.0' 
      compile 'com.squareup.okhttp3:logging-interceptor:3.9.0' 
   } 
```

我们将我们的 Retrofit 和 Okhttp 更新到最新版本。我们为以下内容添加了依赖项：

+   Retrofit 库

+   Gson 转换器，用于反序列化 API 响应

+   Okhttp 库

+   Okhttp 的日志拦截器，以便我们可以记录 API 调用的情况

在同步我们的 Gradle 配置之后，我们准备好开始了！

# 定义 Retrofit 服务

Retrofit 将您的 HTTP API 转换为 Kotlin 接口。在 API 包中创建一个名为`JournalerBackendService`的接口。让我们在其中放入一些代码：

```kt
    package com.journaler.api 

    import com.journaler.model.Note 
    import com.journaler.model.Todo 
    import retrofit2.Call 
    import retrofit2.http.* 

    interface JournalerBackendService { 

      @POST("user/authenticate") 
      fun login( 
            @HeaderMap headers: Map<String, String>, 
            @Body payload: UserLoginRequest 
      ): Call<JournalerApiToken> 

      @GET("entity/note") 
      fun getNotes( 
            @HeaderMap headers: Map<String, String> 
      ): Call<List<Note>> 

      @GET("entity/todo") 
      fun getTodos( 
            @HeaderMap headers: Map<String, String> 
      ): Call<List<Todo>> 

      @PUT("entity/note") 
      fun publishNotes( 
            @HeaderMap headers: Map<String, String>, 
            @Body payload: List<Note> 
      ): Call<Unit> 

      @PUT("entity/todo") 
      fun publishTodos( 
            @HeaderMap headers: Map<String, String>, 
            @Body payload: List<Todo> 
      ): Call<Unit> 

      @DELETE("entity/note") 
      fun removeNotes( 
            @HeaderMap headers: Map<String, String>, 
            @Body payload: List<Note> 
      ): Call<Unit> 

      @DELETE("entity/todo") 
      fun removeTodos( 
            @HeaderMap headers: Map<String, String>, 
            @Body payload: List<Todo> 
      ): Call<Unit> 

    } 
```

在这个接口中我们有什么？我们定义了一系列调用，可以执行以下操作：

+   用户身份验证：这将接受请求标头和包含用户凭据的`UserLoginRequest`类的实例。它将用作我们调用的有效负载。执行调用将返回一个包装的`JournalerApiToken`实例。我们将需要一个令牌用于所有其他调用，并将其内容放入每个调用的标头中。

+   获取`Notes`和`TODOs`：这将接受包含身份验证令牌的请求标头。作为调用的结果，我们会得到一个包装的`Note`或`Todo`类实例的列表。

+   `Notes`和`TODOs`放置（当我们向服务器发送新内容时）：这将接受包含身份验证令牌的请求标头。调用的有效负载将是`Note`或`Todo`类实例的列表。对于这些调用，我们不会返回任何重要数据。重要的是响应代码是正数。

+   删除`Notes`和`TODOs`--这也将接受包含身份验证令牌的请求标头。调用的有效负载将是要从我们的远程后端服务器实例中删除的`Note`或`Todo`类实例的列表。对于这些调用，我们不会返回任何重要数据。重要的是响应代码是正数。

每个都有一个表示 HTTP 方法和路径的适当注释。我们还使用注释来标记有效负载主体和标头映射。

# 构建一个 Retrofit 服务实例

现在，在我们描述了我们的服务之后，我们需要一个真正的 Retrofit 实例，我们将用它来触发 API 调用。首先，我们将介绍一些额外的类。我们将在`TokenManager`对象中保存最新的令牌实例：

```kt
    package com.journaler.api 
     object TokenManager { 
       var currentToken = JournalerApiToken("", -1) 
     } 
```

我们还将有一个用于获取 API 调用标头映射的对象，名为`BackendServiceHeaderMap`，如下所示：

```kt
    package com.journaler.api 

    object BackendServiceHeaderMap { 

     fun obtain(authorization: Boolean = false): Map<String, String> { 
        val map = mutableMapOf( 
                Pair("Accept", "*/*"), 
                Pair("Content-Type", "application/json; charset=UTF-8") 
        ) 
        if (authorization) { 
            map["Authorization"] = "Bearer
             ${TokenManager.currentToken.token}" 
        } 
        return map 
    } 

   } 
```

现在我们可以向您展示如何构建`Retrofit`实例。创建一个名为`BackendServiceRetrofit`的新对象，并确保它看起来像这样：

```kt
    package com.journaler.api 

    import okhttp3.OkHttpClient 
    import okhttp3.logging.HttpLoggingInterceptor 
    import retrofit2.Retrofit 
    import retrofit2.converter.gson.GsonConverterFactory 
    import java.util.concurrent.TimeUnit 

    object BackendServiceRetrofit { 

      fun obtain( 
            readTimeoutInSeconds: Long = 1, 
            connectTimeoutInSeconds: Long = 1 
      ): Retrofit { 
        val loggingInterceptor = HttpLoggingInterceptor() 
        loggingInterceptor.level 
      = HttpLoggingInterceptor.Level.BODY 
        return Retrofit.Builder() 
                .baseUrl("http://127.0.0.1") 
                .addConverterFactory(GsonConverterFactory.create()) 
                .client( 
                        OkHttpClient 
                                .Builder() 
                                .addInterceptor(loggingInterceptor) 
                                .readTimeout(readTimeoutInSeconds,
                                TimeUnit.SECONDS) 
                                  .connectTimeout
                                (connectTimeoutInSeconds,
                                TimeUnit.SECONDS) 
                                .build() 
                ) 
                .build() 
     } 

    } 
```

调用`obtain()`方法将返回一个准备好发出 API 调用的`Retrofit`实例。我们创建了一个`Retrofit`实例，其后端基本 URL 设置为本地主机。我们还传递了 Gson 转换器工厂，用作 JSON 反序列化的机制。最重要的是，我们传递了我们将使用的客户端实例，并创建了一个新的 OkHttp 客户端。

# 使用 Kotson 库介绍 Gson

JSON 序列化和反序列化对于每个 Android 应用程序都非常重要，并且经常被使用。为此，我们将使用由 Google 开发的 Gson 库。此外，我们将使用 Kotson 和 Kotlin 绑定来使用 Gson。所以，让我们开始吧！

首先，我们需要根据以下内容为我们的`build.gradle`配置提供依赖项：

```kt
    apply plugin: "com.android.application" 
    apply plugin: "kotlin-android" 
    apply plugin: "kotlin-android-extensions" 
    ... 
    dependencies { 
      ... 
      compile 'com.google.code.gson:gson:2.8.0' 
      compile 'com.github.salomonbrys.kotson:kotson:2.3.0' 
      ... 
    } 
```

我们将更新我们的代码，使用 Gson 与 Kotson 绑定进行位置序列化/反序列化在数据库管理中。首先，我们需要对`Db`类进行一些小改动：

```kt
    class DbHelper(dbName: String, val version: Int) :
    SQLiteOpenHelper( 
      Journaler.ctx, dbName, null, version 
    ) { 

    companion object { 
        val ID: String = "_id" 
        val TABLE_TODOS = "todos" 
        val TABLE_NOTES = "notes" 
        val COLUMN_TITLE: String = "title" 
        val COLUMN_MESSAGE: String = "message" 
        val COLUMN_LOCATION: String = "location" 
        val COLUMN_SCHEDULED: String = "scheduled" 
    } 
    ... 
    private val createTableNotes =  """ 
                                    CREATE TABLE if not exists
                                     $TABLE_NOTES 
                                    ( 
                                        $ID integer PRIMARY KEY
                                        autoincrement, 
                                        $COLUMN_TITLE text, 
                                        $COLUMN_MESSAGE text, 
                                        $COLUMN_LOCATION text 
                                    ) 
                                    """ 

    private val createTableTodos =  """ 
                                    CREATE TABLE if not exists
                                     $TABLE_TODOS 
                                    ( 
                                        $ID integer PRIMARY KEY
                                         autoincrement, 
                                        $COLUMN_TITLE text, 
                                        $COLUMN_MESSAGE text, 
                                        $COLUMN_SCHEDULED integer, 
                                        $COLUMN_LOCATION text 
                                    ) 
                                    """ 
    ... 
   } 
```

正如您所见，我们改变了位置信息处理。现在，我们不再有位置纬度和经度列，而是只有一个数据库列--`location`。类型为`Text`。我们将保存由 Gson 库生成的序列化的`Location`类值。此外，当我们检索序列化的值时，我们将使用 Gson 将它们反序列化为`Location`类实例。

现在，我们必须实际使用 Gson。打开`Db.kt`并更新它以使用 Gson 序列化和反序列化`Location`类实例，如下所示：

```kt
    package com.journaler.database 
    ... 
    import com.google.gson.Gson 
    ... 
    import com.github.salomonbrys.kotson.* 

    object Db : Crud<DbModel> { 
      ... 
      private val gson = Gson() 
      ... 
      override fun insert(what: Collection<DbModel>): Boolean { 
        ... 
        what.forEach { 
            item -> 
            when (item) { 
                is Entry -> { 
                    ... 
                    values.put(DbHelper.COLUMN_LOCATION,
                     gson.toJson(item.location)) 
                    ... 
            } 
        } 
        ... 
        return success 
    } 
    ... 
    override fun update(what: Collection<DbModel>): Boolean { 
        ... 
        what.forEach { 
            item -> 
            when (item) { 
                is Entry -> { 
                    ... 
                    values.put(DbHelper.COLUMN_LOCATION,
                    gson.toJson(item.location)) 
                } 
       ... 
        return result 
    } 
    ... 
    override fun select(args: Pair<String, String>, clazz:  
    KClass<DbModel>): List<DbModel> { 
        return select(listOf(args), clazz) 
    } 

    override fun select( 
        args: Collection<Pair<String, String>>, clazz: Kclass<DbModel> 
    ): List<DbModel> { 
        ... 
        if (clazz.simpleName == Note::class.simpleName) { 
            val result = mutableListOf<DbModel>() 
            val cursor = db.query( 
                ... 
            ) 
            while (cursor.moveToNext()) { 
                ... 
                val locationIdx =
                cursor.getColumnIndexOrThrow(DbHelper.COLUMN_LOCATION) 
                val locationJson = cursor.getString(locationIdx) 
                val location = gson.fromJson<Location>(locationJson) 
                val note = Note(title, message, location) 
                note.id = id 
                result.add(note) 
            } 
            cursor.close() 
            return result 
        } 
        if (clazz.simpleName == Todo::class.simpleName) { 
                ... 
            ) 
            while (cursor.moveToNext()) { 
                ... 
                val locationIdx =
                cursor.getColumnIndexOrThrow(DbHelper.COLUMN_LOCATION) 
                val locationJson = cursor.getString(locationIdx) 
                val location = gson.fromJson<Location>(locationJson) 
                ... 
                val todo = Todo(title, message, location, scheduledFor) 
                todo.id = id 
                result.add(todo) 
            } 
            cursor.close() 
            return result 
        } 
        db.close() 
        throw IllegalArgumentException("Unsupported entry type: 
        $clazz") 
      } 
   }  
```

正如您所见，在上述代码中，使用 Gson 进行更新非常简单。我们依赖于从 Gson 类实例访问的以下两个 Gson 库方法：

+   `fromJson<T>()`

+   `toJson()`

由于 Kotson 和 Kotlin 绑定，我们可以使用`fromJson<T>()`方法对我们序列化的数据使用参数化类型。

# 还有什么其他的？

现在，我们将列出一些 Retrofit 和 Gson 的替代方案。在外部，有一个庞大的开源社区，每天都在做出伟大的事情。您不必使用我们提供的任何库。您可以选择任何替代方案，甚至创建自己的实现！

# Retrofit 替代方案

正如其主页所说，Volley 是一个使 Android 应用程序的网络工作更加简单和更快的 HTTP 库。Volley 提供的一些关键功能包括：

+   自动调度网络请求

+   多个并发网络连接

+   透明的磁盘和内存响应缓存与标准 HTTP 缓存一致性

+   支持请求优先级。

+   取消请求 API

+   易于定制

+   强有力的排序

+   调试和跟踪工具

主页--[`github.com/google/volley`](https://github.com/google/volley)。

# Gson 替代方案

Jackson 是一个低级别的 JSON 解析器。它与 Java StAX 解析器非常相似，用于 XML。Jackson 提供的一些关键功能包括：

+   非常快速和方便

+   广泛的注释支持

+   流式读取和写入

+   树模型

+   开箱即用的 JAX-RS 支持

+   集成对二进制内容的支持

主页--[`github.com/FasterXML/jackson`](https://github.com/FasterXML/jackson)。

# 执行我们的第一个 API 调用

我们定义了一个带有所有 API 调用的 Retrofit 服务，但我们还没有将任何东西连接到它。现在是使用它的时候了。我们将扩展我们的代码以使用 Retrofit。每个 API 调用都可以同步或异步执行。我们将向您展示两种方式。您还记得我们将 Retrofit 服务的基本 URL 设置为本地主机吗？这意味着我们将需要一个本地后端实例来响应我们的 HTTP 请求。由于后端实现不是本书的主题，我们将把它留给您来创建一个简单的服务来响应此请求。您可以使用任何您喜欢的编程语言来实现它，比如 Kotlin、Java、Python 和 PHP。

如果您不耐烦，不想为处理 HTTP 请求实现自己的应用程序，您可以覆盖基本 URL，Notes 和 TODOs 路径，如下例所示，并使用后端实例进行尝试：

+   基本 URL--[`static.milosvasic.net/json/journaler`](http://static.milosvasic.net/json/journaler)

+   登录 POST 到目标：

```kt
        @POST("authenticate") 
        // @POST("user/authenticate") 
        fun login( 
            ... 
        ): Call<JournalerApiToken> 
```

+   `Notes` `GET`到目标：

```kt
        @GET("notes") 
        // @GET("entity/note") 
        fun getNotes( 
            ... 
        ): Call<List<Note>> 
```

+   `TODOs` `GET`到目标：

```kt
        @GET("todos") 
        // @GET("entity/todo") 
       fun getTodos( 
            ... 
       ): Call<List<Todo>> 
```

这样，我们将针对远程后端实例返回我们的存根`Notes`和`TODOs`。现在打开您的`JournalerBackendService`接口，并将其扩展如下：

```kt
    interface JournalerBackendService { 
      companion object { 
        fun obtain(): JournalerBackendService { 
            return BackendServiceRetrofit 
                    .obtain() 
                    .create(JournalerBackendService::class.java) 
        } 
     } 
      ... 
    } 
```

我们刚刚添加的方法将为我们提供一个使用 Retrofit 的`JournalerBackendService`实例。通过这个，我们将触发所有我们的调用。打开`MainService`类。找到`synchronize()`方法。记住我们在那里放了一个睡眠来模拟与后端的通信。现在，我们将用真实的后端调用替换它：

```kt
    /** 
    * Authenticates user synchronously, 
    * then executes async calls for notes and TODOs fetching. 
    * Pay attention on synchronously triggered call via execute() 
      method. 
    * Its asynchronous equivalent is: enqueue(). 
    */ 
    override fun synchronize() { 
        executor.execute { 
            Log.i(tag, "Synchronizing data [ START ]") 
            var headers = BackendServiceHeaderMap.obtain() 
            val service = JournalerBackendService.obtain() 
            val credentials = UserLoginRequest("username", "password") 
            val tokenResponse = service 
                    .login(headers, credentials) 
                    .execute() 
            if (tokenResponse.isSuccessful) { 
                val token = tokenResponse.body() 
                token?.let { 
                    TokenManager.currentToken = token 
                    headers = BackendServiceHeaderMap.obtain(true) 
                    fetchNotes(service, headers) 
                    fetchTodos(service, headers) 
                } 
            } 
            Log.i(tag, "Synchronizing data [ END ]") 
        } 
    } 

    /** 
    * Fetches notes asynchronously. 
    * Pay attention on enqueue() method 
    */ 
    private fun fetchNotes( 
            service: JournalerBackendService, headers: Map<String,  
    String> 
    ) { 
        service 
            .getNotes(headers) 
            .enqueue( 
            object : Callback<List<Note>> { 
              verride fun onResponse( 
               call: Call<List<Note>>?, response: Response<List<Note>>? 
                            ) { 
                                response?.let { 
                                    if (response.isSuccessful) { 
                                        val notes = response.body() 
                                        notes?.let { 
                                            Db.insert(notes) 
                                        } 
                                    } 
                                } 
                            } 

                            override fun onFailure(call: 
                            Call<List<Note>>?, t: Throwable?) { 
                                Log.e(tag, "We couldn't fetch notes.") 
                            } 
                        } 
                ) 
     } 

     /** 
     * Fetches TODOs asynchronously. 
     * Pay attention on enqueue() method 
     */ 
     private fun fetchTodos( 
            service: JournalerBackendService, headers: Map<String,  
      String> 
     ) { 
        service 
                .getTodos(headers) 
                .enqueue( 
                        object : Callback<List<Todo>> { 
                            override fun onResponse( 
                                    call: Call<List<Todo>>?, response:
         Response<List<Todo>>? 
                            ) { 
                                response?.let { 
                                    if (response.isSuccessful) { 
                                        val todos = response.body() 
                                        todos?.let { 
                                            Db.insert(todos) 
                                        } 
                                    } 
                                } 
                            } 

                            override fun onFailure(call:
                            Call<List<Todo>>?, t: Throwable?) { 
                                Log.e(tag, "We couldn't fetch notes.") 
                            } 
                        } 
                 ) 
     } 
```

慢慢分析代码，花点时间！有很多事情要做！首先，我们将创建标题和 Journaler 后端服务的实例。然后，我们通过触发`execute()`方法同步执行身份验证。我们收到了`Response<JournalerApiToken>`。`JournalerApiToken`实例包装在`Response`类实例中。在我们检查响应是否成功，并且我们实际上收到并反序列化了`JournalerApiToken`之后，我们将其设置为`TokenManager`。最后，我们触发`Notes`和`TODOs`检索的异步调用。

`enqueue()`方法触发异步操作，并且作为参数接受 Retrofit 回调具体化。我们将与同步调用做同样的事情。我们将检查它是否成功，以及是否有数据。如果一切正常，我们将把所有实例传递给我们的数据库管理器进行保存。

我们只实现了`Notes`和`TODOs`的检索。对于其余的 API 调用，我们将把它留给您来实现。这是学习 Retrofit 的一个很好的方法！

让我们构建一个应用程序并运行它。当应用程序及其主服务启动时，API 调用将被执行。通过 OkHttp 过滤 Logcat 输出。观察以下内容。

身份验证日志行：

+   请求：

```kt
 D/OkHttp: --> POST 
 http://static.milosvasic.net/jsons/journaler/authenticate 
        D/OkHttp: Content-Type: application/json; charset=UTF-8 
        D/OkHttp: Content-Length: 45 
        D/OkHttp: Accept: */* 
        D/OkHttp: {"password":"password","username":"username"} 
        D/OkHttp: --> END POST (45-byte body) 
```

+   响应：

```kt
 D/OkHttp: <-- 200 OK 
 http://static.milosvasic.net/jsons/journaler/
 authenticate/ (302ms) 
       D/OkHttp: Date: Sat, 23 Sep 2017 15:46:27 GMT 
       D/OkHttp: Server: Apache 
       D/OkHttp: Keep-Alive: timeout=5, max=99 
       D/OkHttp: Connection: Keep-Alive 
       D/OkHttp: Transfer-Encoding: chunked 
       D/OkHttp: Content-Type: text/html 
       D/OkHttp: { 
       D/OkHttp:   "id_token": "stub_token_1234567", 
       D/OkHttp:   "expires": 10000 
       D/OkHttp: } 
       D/OkHttp: <-- END HTTP (58-byte body) 
```

`Notes`日志行：

+   请求：

```kt
 D/OkHttp: --> GET 
 http://static.milosvasic.net/jsons/journaler/notes 
        D/OkHttp: Accept: */* 
        D/OkHttp: Authorization: Bearer stub_token_1234567 
        D/OkHttp: --> END GET 
```

+   响应：

```kt
 D/OkHttp: <-- 200 OK 
 http://static.milosvasic.net/jsons/journaler/notes/ (95ms) 
        D/OkHttp: Date: Sat, 23 Sep 2017 15:46:28 GMT 
        D/OkHttp: Server: Apache 
        D/OkHttp: Keep-Alive: timeout=5, max=97 
        D/OkHttp: Connection: Keep-Alive 
        D/OkHttp: Transfer-Encoding: chunked 
        D/OkHttp: Content-Type: text/html 
        D/OkHttp: [ 
        D/OkHttp:   { 
        D/OkHttp:     "title": "Test note 1", 
        D/OkHttp:     "message": "Test message 1", 
        D/OkHttp:     "location": { 
        D/OkHttp:       "latitude": 10000, 
        D/OkHttp:       "longitude": 10000 
        D/OkHttp:     } 
        D/OkHttp:   }, 
        D/OkHttp:   { 
        D/OkHttp:     "title": "Test note 2", 
        D/OkHttp:     "message": "Test message 2", 
        D/OkHttp:     "location": { 
        D/OkHttp:       "latitude": 10000, 
        D/OkHttp:       "longitude": 10000 
        D/OkHttp:     } 
        D/OkHttp:   }, 
        D/OkHttp:   { 
        D/OkHttp:     "title": "Test note 3", 
        D/OkHttp:     "message": "Test message 3", 
        D/OkHttp:     "location": { 
        D/OkHttp:       "latitude": 10000, 
        D/OkHttp:       "longitude": 10000 
        D/OkHttp:     } 
        D/OkHttp:   } 
        D/OkHttp: ] 
        D/OkHttp: <-- END HTTP (434-byte body) 
```

`TODOs`日志行：

+   请求：这是我们做的请求部分的一个例子：

```kt
 D/OkHttp: --> GET
 http://static.milosvasic.net/jsons/journaler/todos 
        D/OkHttp: Accept: */* 
        D/OkHttp: Authorization: Bearer stub_token_1234567 
        D/OkHttp: --> END GET 
```

+   响应：这是我们收到的响应的一个例子：

```kt
 D/OkHttp: <-- 200 OK
 http://static.milosvasic.net/jsons/journaler/todos/ (140ms) 
       D/OkHttp: Date: Sat, 23 Sep 2017 15:46:28 GMT 
       D/OkHttp: Server: Apache 
       D/OkHttp: Keep-Alive: timeout=5, max=99 
       D/OkHttp: Connection: Keep-Alive 
       D/OkHttp: Transfer-Encoding: chunked 
       D/OkHttp: Content-Type: text/html 
       D/OkHttp: [ 
       D/OkHttp:   { 
       D/OkHttp:     "title": "Test todo 1", 
       D/OkHttp:     "message": "Test message 1", 
       D/OkHttp:     "location": { 
       D/OkHttp:       "latitude": 10000, 
       D/OkHttp:       "longitude": 10000 
       D/OkHttp:     }, 
       D/OkHttp:     "scheduledFor": 10000 
       D/OkHttp:   }, 
       D/OkHttp:   { 
       D/OkHttp:     "title": "Test todo 2", 
       D/OkHttp:     "message": "Test message 2", 
       D/OkHttp:     "location": { 
       D/OkHttp:       "latitude": 10000, 
       D/OkHttp:       "longitude": 10000 
       D/OkHttp:     }, 
       D/OkHttp:     "scheduledFor": 10000 
       D/OkHttp:   }, 
       D/OkHttp:   { 
       D/OkHttp:     "title": "Test todo 3", 
       D/OkHttp:     "message": "Test message 3", 
       D/OkHttp:     "location": { 
       D/OkHttp:       "latitude": 10000, 
       D/OkHttp:       "longitude": 10000 
       D/OkHttp:     }, 
       D/OkHttp:     "scheduledFor": 10000 
       D/OkHttp:   } 
       D/OkHttp: ] 
       D/OkHttp: <-- END HTTP (515-byte body) 
```

恭喜！您已经实现了您的第一个 Retrofit 服务！现在是时候实现其余的调用。还要进行一些代码重构！这是一个小作业任务给你。更新您的服务，使其可以接受登录凭据。在我们当前的代码中，我们硬编码了用户名和密码。您的任务将是重构代码并传递参数化的凭据。

可选地，改进代码，使其不再可能在同一时刻多次执行相同的调用。我们将这留作我们以前工作的遗留问题。

# 内容提供程序

现在是时候进一步改进我们的应用程序并向您介绍 Android 内容提供程序。内容提供程序是 Android 框架提供的顶级强大功能之一。内容提供程序的目的是什么？顾名思义，内容提供程序的目的是管理我们的应用程序存储的数据或其他应用程序存储的数据的访问。它们提供了一种机制来与其他应用程序共享数据，并为数据访问提供了安全机制，这些数据可能来自同一进程，也可能不来自同一进程。

看一下下面的插图，显示内容提供程序如何管理对共享存储的访问：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/ad7d8f5f-eed6-4480-988f-3d2429c76339.png)

我们计划与其他应用程序共享`Notes`和`TODOs`数据。由于抽象层内容提供者提供的抽象层，很容易在不影响上层的情况下对存储实现层进行更改。因此，即使你不打算与其他应用程序共享任何数据，你也可以使用内容提供者。例如，我们可以完全替换持久性机制，从 SQLite 到完全不同的东西。看一下下面的插图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/0109ab05-42bf-40e3-87d1-d34dd8ee5ebd.png)

如果你不确定是否需要内容提供者，这就是你应该实现它的时候：

+   如果你计划与其他应用程序共享你的应用程序数据

+   如果你计划从你的应用程序复制和粘贴复杂数据或文件到其他应用程序

+   如果你计划支持自定义搜索建议

Android 框架已经定义了一个内容提供者，你可以使用它来管理联系人、音频、视频或其他文件。内容提供者不仅限于 SQLite 访问，你也可以用它来处理其他结构化数据。

让我们再次强调主要的好处：

+   访问数据的权限

+   抽象数据层

所以，正如我们已经说过的，我们计划支持从 Journaler 应用程序暴露数据。在创建内容提供者之前，我们必须注意，这将需要重构当前的代码。不要担心，我们将向你介绍内容提供者，并解释给你所有我们所做的重构。在我们完成实现和重构之后，我们将创建一个示例客户端应用程序，该应用程序将使用我们的内容提供者并触发所有 CRUD 操作。

让我们创建一个`ContentProvider`类。创建一个名为`provider`的新包，并创建一个`JournalerProvider`类，继承`ContentProvider`类。

类开始：

```kt
    package com.journaler.provider 

    import android.content.* 
    import android.database.Cursor 
    import android.net.Uri 
    import com.journaler.database.DbHelper 
    import android.content.ContentUris 
    import android.database.SQLException 
    import android.database.sqlite.SQLiteDatabase 
    import android.database.sqlite.SQLiteQueryBuilder 
    import android.text.TextUtils 

    class JournalerProvider : ContentProvider() { 

      private val version = 1 
      private val name = "journaler" 
      private val db: SQLiteDatabase by lazy { 
        DbHelper(name, version).writableDatabase 
    } 

```

定义一个`companion`对象：

```kt
     companion object { 
        private val dataTypeNote = "note" 
        private val dataTypeNotes = "notes" 
        private val dataTypeTodo = "todo" 
        private val dataTypeTodos = "todos" 
        val AUTHORITY = "com.journaler.provider" 
        val URL_NOTE = "content://$AUTHORITY/$dataTypeNote" 
        val URL_TODO = "content://$AUTHORITY/$dataTypeTodo" 
        val URL_NOTES = "content://$AUTHORITY/$dataTypeNotes" 
        val URL_TODOS = "content://$AUTHORITY/$dataTypeTodos" 
        private val matcher = UriMatcher(UriMatcher.NO_MATCH) 
        private val NOTE_ALL = 1 
        private val NOTE_ITEM = 2 
        private val TODO_ALL = 3 
        private val TODO_ITEM = 4 
    } 

```

类初始化：

```kt
    /** 
     * We register uri paths in the following format: 
     * 
     * <prefix>://<authority>/<data_type>/<id> 
     * <prefix> - This is always set to content:// 
     * <authority> - Name for the content provider 
     * <data_type> - The type of data we provide in this Uri 
     * <id> - Record ID. 
     */ 
    init { 
        /** 
         * The calls to addURI() go here, 
         * for all of the content URI patterns that the provider should
          recognize. 
         * 
         * First: 
         * 
         * Sets the integer value for multiple rows in notes (TODOs) to 
         1\. 
         * Notice that no wildcard is used in the path. 
         * 
         * Second: 
         * 
         * Sets the code for a single row to 2\. In this case, the "#"
         wildcard is 
         * used. "content://com.journaler.provider/note/3" matches, but 
         * "content://com.journaler.provider/note doesn't. 
         * 
         * The same applies for TODOs. 
         * 
         * addUri() params: 
         * 
         * authority    - String: the authority to match 
         * 
         * path         - String: the path to match. 
         *              * may be used as a wild card for any text, 
         *              and # may be used as a wild card for numbers. 
         * 
         * code              - int: the code that is returned when a
        URI 
         *              is matched against the given components. 
         */ 
        matcher.addURI(AUTHORITY, dataTypeNote, NOTE_ALL) 
        matcher.addURI(AUTHORITY, "$dataTypeNotes/#", NOTE_ITEM) 
        matcher.addURI(AUTHORITY, dataTypeTodo, TODO_ALL) 
        matcher.addURI(AUTHORITY, "$dataTypeTodos/#", TODO_ITEM) 
    } 
```

重写`onCreate()`方法：

```kt
     /** 
     * True - if the provider was successfully loaded 
     */ 
    override fun onCreate() = true 
```

插入操作如下：

```kt
     override fun insert(uri: Uri?, values: ContentValues?): Uri { 
        uri?.let { 
            values?.let { 
                db.beginTransaction() 
                val (url, table) = getParameters(uri) 
                if (!TextUtils.isEmpty(table)) { 
                    val inserted = db.insert(table, null, values) 
                    val success = inserted > 0 
                    if (success) { 
                        db.setTransactionSuccessful() 
                    } 
                    db.endTransaction() 
                    if (success) { 
                        val resultUrl = ContentUris.withAppendedId
                        (Uri.parse(url), inserted) 
                        context.contentResolver.notifyChange(resultUrl,
                        null) 
                        return resultUrl 
                    } 
                } else { 
                    throw SQLException("Insert failed, no table for
                    uri: " + uri) 
                } 
            } 
        } 
        throw SQLException("Insert failed: " + uri) 
    } 
```

更新操作如下：

```kt
     override fun update( 
            uri: Uri?, 
            values: ContentValues?, 
            where: String?, 
            whereArgs: Array<out String>? 
    ): Int { 
        uri?.let { 
            values?.let { 
                db.beginTransaction() 
                val (_, table) = getParameters(uri) 
                if (!TextUtils.isEmpty(table)) { 
                    val updated = db.update(table, values, where,
                     whereArgs) 
                    val success = updated > 0 
                    if (success) { 
                        db.setTransactionSuccessful() 
                    } 
                    db.endTransaction() 
                    if (success) { 
                        context.contentResolver.notifyChange(uri, null) 
                        return updated 
                    } 
                } else { 
                    throw SQLException("Update failed, no table for
                     uri: " + uri) 
                } 
            } 
        } 
        throw SQLException("Update failed: " + uri) 
    } 
```

删除操作如下：

```kt
    override fun delete( 
            uri: Uri?, 
            selection: String?, 
            selectionArgs: Array<out String>? 
    ): Int { 
        uri?.let { 
            db.beginTransaction() 
            val (_, table) = getParameters(uri) 
            if (!TextUtils.isEmpty(table)) { 
                val count = db.delete(table, selection, selectionArgs) 
                val success = count > 0 
                if (success) { 
                    db.setTransactionSuccessful() 
                } 
                db.endTransaction() 
                if (success) { 
                    context.contentResolver.notifyChange(uri, null) 
                    return count 
                } 
            } else { 
                throw SQLException("Delete failed, no table for uri: "
               + uri) 
            } 
        } 
        throw SQLException("Delete failed: " + uri) 
    } 
```

执行查询：

```kt
     override fun query( 
            uri: Uri?, 
            projection: Array<out String>?, 
            selection: String?, 
            selectionArgs: Array<out String>?, 
            sortOrder: String? 
     ): Cursor { 
        uri?.let { 
            val stb = SQLiteQueryBuilder() 
            val (_, table) = getParameters(uri) 
            stb.tables = table 
            stb.setProjectionMap(mutableMapOf<String, String>()) 
            val cursor = stb.query(db, projection, selection,
             selectionArgs, null, null, null) 
            // register to watch a content URI for changes 
            cursor.setNotificationUri(context.contentResolver, uri) 
            return cursor 
        } 
        throw SQLException("Query failed: " + uri) 
    } 

    /** 
     * Return the MIME type corresponding to a content URI. 
     */ 
    override fun getType(p0: Uri?): String = when (matcher.match(p0)) { 
        NOTE_ALL -> { 
            "${ContentResolver.
            CURSOR_DIR_BASE_TYPE}/vnd.com.journaler.note.items" 
        } 
        NOTE_ITEM -> { 
            "${ContentResolver.
             CURSOR_ITEM_BASE_TYPE}/vnd.com.journaler.note.item" 
        } 
        TODO_ALL -> { 
            "${ContentResolver.
             CURSOR_DIR_BASE_TYPE}/vnd.com.journaler.todo.items" 
        } 
        TODO_ITEM -> { 
            "${ContentResolver.
            CURSOR_ITEM_BASE_TYPE}/vnd.com.journaler.todo.item" 
        } 
        else -> throw IllegalArgumentException
        ("Unsupported Uri [ $p0 ]") 
    } 
```

类结束：

```kt
     private fun getParameters(uri: Uri): Pair<String, String> { 
        if (uri.toString().startsWith(URL_NOTE)) { 
            return Pair(URL_NOTE, DbHelper.TABLE_NOTES) 
        } 
        if (uri.toString().startsWith(URL_NOTES)) { 
            return Pair(URL_NOTES, DbHelper.TABLE_NOTES) 
        } 
        if (uri.toString().startsWith(URL_TODO)) { 
            return Pair(URL_TODO, DbHelper.TABLE_TODOS) 
        } 
        if (uri.toString().startsWith(URL_TODOS)) { 
            return Pair(URL_TODOS, DbHelper.TABLE_TODOS) 
        } 
        return Pair("", "") 
       } 

     }  
```

从上到下，我们做了以下工作：

+   定义数据库名称和版本

+   定义数据库实例的延迟初始化

+   定义我们将用于访问数据的 URI(s)

+   实现了所有的 CRUD 操作

+   为数据定义 MIME 类型

现在，当你有一个内容提供者实现时，需要在你的`manifest`中注册它，如下所示：

```kt
    <manifest xmlns:android=
    "http://schemas.android.com/apk/res/android" 
    package="com.journaler"> 
    ... 
      <application 
        ... 
      > 
        ... 
        <provider 
            android:exported="true" 
            android:name="com.journaler.provider.JournalerProvider" 
            android:authorities="com.journaler.provider" /> 
        ... 
     </application> 
    ... 
    </manifest> 
```

观察。我们将`exported`属性设置为`True`。这是什么意思？这意味着，如果为`True`，Journaler 提供者可供其他应用程序使用。任何应用程序都可以使用提供者的内容 URI 来访问数据。另一个重要的属性是`multiprocess`。如果应用程序在多个进程中运行，此属性确定是否创建 Journaler 提供者的多个实例。如果为`True`，每个应用程序的进程都有自己的内容提供者实例。

让我们继续。在`Crud`接口中，如果你还没有，将这个添加到`companion`对象中：

```kt
    companion object { 
        val BROADCAST_ACTION = "com.journaler.broadcast.crud" 
        val BROADCAST_EXTRAS_KEY_CRUD_OPERATION_RESULT = "crud_result" 
   }  
```

我们将把我们的`Db`类重命名为 Content。更新`Content`实现，如下所示，以使用`JournalerProvider`：

```kt
    package com.journaler.database 

    import android.content.ContentValues 
    import android.location.Location 
    import android.net.Uri 
    import android.util.Log 
    import com.github.salomonbrys.kotson.fromJson 
    import com.google.gson.Gson 
    import com.journaler.Journaler 
    import com.journaler.model.* 
    import com.journaler.provider.JournalerProvider 

    object Content { 

      private val gson = Gson() 
      private val tag = "Content" 

      val NOTE = object : Crud<Note> { ... 

```

注意插入操作：

```kt

     ... 
     override fun insert(what: Note): Long { 
       val inserted = insert(listOf(what)) 
       if (!inserted.isEmpty()) return inserted[0] 
         return 0 
     } 

     override fun insert(what: Collection<Note>): List<Long> { 
        val ids = mutableListOf<Long>() 
        what.forEach { item -> 
           val values = ContentValues() 
           values.put(DbHelper.COLUMN_TITLE, item.title) 
           values.put(DbHelper.COLUMN_MESSAGE, item.message) 
           values.put(DbHelper.COLUMN_LOCATION,
           gson.toJson(item.location)) 
           val uri = Uri.parse(JournalerProvider.URL_NOTE) 
           val ctx = Journaler.ctx 
           ctx?.let { 
             val result = ctx.contentResolver.insert(uri, values) 
             result?.let { 
                 try { 
                      ids.add(result.lastPathSegment.toLong()) 
                  } catch (e: Exception) { 
                  Log.e(tag, "Error: $e") 
                } 
             } 
           } 
         } 
         return ids 
        } ... 
```

`Note`更新操作：

```kt
    .. 
    override fun update(what: Note) = update(listOf(what)) 

    override fun update(what: Collection<Note>): Int { 
      var count = 0 
      what.forEach { item -> 
          val values = ContentValues() 
          values.put(DbHelper.COLUMN_TITLE, item.title) 
          values.put(DbHelper.COLUMN_MESSAGE, item.message) 
          values.put(DbHelper.COLUMN_LOCATION,
          gson.toJson(item.location)) 
          val uri = Uri.parse(JournalerProvider.URL_NOTE) 
          val ctx = Journaler.ctx 
          ctx?.let { 
            count += ctx.contentResolver.update( 
              uri, values, "_id = ?", arrayOf(item.id.toString()) 
            ) 
          } 
         } 
         return count 
        } ... 
```

注意删除操作：

```kt
   ... 
   override fun delete(what: Note): Int = delete(listOf(what)) 

   override fun delete(what: Collection<Note>): Int { 
     var count = 0 
     what.forEach { item -> 
       val uri = Uri.parse(JournalerProvider.URL_NOTE) 
       val ctx = Journaler.ctx 
       ctx?.let { 
         count += ctx.contentResolver.delete( 
         uri, "_id = ?", arrayOf(item.id.toString()) 
       ) 
     } 
   } 
   return count 
  } ...  
```

`Note`选择操作：

```kt
     ...  
     override fun select(args: Pair<String, String> 
      ): List<Note> = select(listOf(args)) 

     override fun select(args: Collection<Pair<String, String>>):  
     List<Note> { 
            val items = mutableListOf<Note>() 
            val selection = StringBuilder() 
            val selectionArgs = mutableListOf<String>() 
            args.forEach { arg -> 
                selection.append("${arg.first} == ?") 
                selectionArgs.add(arg.second) 
            } 
            val ctx = Journaler.ctx 
            ctx?.let { 
                val uri = Uri.parse(JournalerProvider.URL_NOTES) 
                val cursor = ctx.contentResolver.query( 
                        uri, null, selection.toString(),
                  selectionArgs.toTypedArray(), null 
                ) 
                while (cursor.moveToNext()) { 
                    val id = cursor.getLong
                    (cursor.getColumnIndexOrThrow(DbHelper.ID)) 
                    val titleIdx = cursor.getColumnIndexOrThrow
                    (DbHelper.COLUMN_TITLE) 
                    val title = cursor.getString(titleIdx) 
                    val messageIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_MESSAGE) 
                    val message = cursor.getString(messageIdx) 
                    val locationIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_LOCATION) 
                    val locationJson = cursor.getString(locationIdx) 
                    val location = gson.fromJson<Location>
                    (locationJson) 
                    val note = Note(title, message, location) 
                    note.id = id 
                    items.add(note) 
                } 
                cursor.close() 
                return items 
            } 
            return items 
        } 

        override fun selectAll(): List<Note> { 
            val items = mutableListOf<Note>() 
            val ctx = Journaler.ctx 
            ctx?.let { 
                val uri = Uri.parse(JournalerProvider.URL_NOTES) 
                val cursor = ctx.contentResolver.query( 
                        uri, null, null, null, null 
                ) 
                while (cursor.moveToNext()) { 
                    val id = cursor.getLong
                    (cursor.getColumnIndexOrThrow(DbHelper.ID)) 
                    val titleIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_TITLE) 
                    val title = cursor.getString(titleIdx) 
                    val messageIdx = cursor.getColumnIndexOrThrow
                    (DbHelper.COLUMN_MESSAGE) 
                    val message = cursor.getString(messageIdx) 
                    val locationIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_LOCATION) 
                    val locationJson = cursor.getString(locationIdx) 
                    val location = gson.fromJson<Location>
                  (locationJson) 
                    val note = Note(title, message, location) 
                    note.id = id 
                    items.add(note) 
                } 
                cursor.close() 
            } 
            return items 
        } 
    }  
```

`Todo`对象定义及其插入操作：

```kt
     ... 
     val TODO = object : Crud<Todo> { 
        override fun insert(what: Todo): Long { 
            val inserted = insert(listOf(what)) 
            if (!inserted.isEmpty()) return inserted[0] 
            return 0 
        } 

        override fun insert(what: Collection<Todo>): List<Long> { 
            val ids = mutableListOf<Long>() 
            what.forEach { item -> 
                val values = ContentValues() 
                values.put(DbHelper.COLUMN_TITLE, item.title) 
                values.put(DbHelper.COLUMN_MESSAGE, item.message) 
                values.put(DbHelper.COLUMN_LOCATION,
                gson.toJson(item.location)) 
                val uri = Uri.parse(JournalerProvider.URL_TODO) 
                values.put(DbHelper.COLUMN_SCHEDULED,   
                item.scheduledFor) 
                val ctx = Journaler.ctx 
                ctx?.let { 
                    val result = ctx.contentResolver.insert(uri, 
                    values) 
                    result?.let { 
                        try { 
                            ids.add(result.lastPathSegment.toLong()) 
                        } catch (e: Exception) { 
                            Log.e(tag, "Error: $e") 
                        } 
                    } 
                } 
            } 
            return ids 
        } ... 
```

`Todo`更新操作：

```kt
     ... 
     override fun update(what: Todo) = update(listOf(what)) 

     override fun update(what: Collection<Todo>): Int { 
        var count = 0 
        what.forEach { item -> 
                val values = ContentValues() 
                values.put(DbHelper.COLUMN_TITLE, item.title) 
                values.put(DbHelper.COLUMN_MESSAGE, item.message) 
                values.put(DbHelper.COLUMN_LOCATION,
                gson.toJson(item.location)) 
                val uri = Uri.parse(JournalerProvider.URL_TODO) 
                values.put(DbHelper.COLUMN_SCHEDULED, 
                item.scheduledFor) 
                val ctx = Journaler.ctx 
                ctx?.let { 
                    count += ctx.contentResolver.update( 
                            uri, values, "_id = ?",
                           arrayOf(item.id.toString()) 
                    ) 
                } 
            } 
            return count 
        } ... 
```

`Todo`删除操作：

```kt
     ... 
     override fun delete(what: Todo): Int = delete(listOf(what)) 

     override fun delete(what: Collection<Todo>): Int { 
            var count = 0 
            what.forEach { item -> 
                val uri = Uri.parse(JournalerProvider.URL_TODO) 
                val ctx = Journaler.ctx 
                ctx?.let { 
                    count += ctx.contentResolver.delete( 
                            uri, "_id = ?", arrayOf(item.id.toString()) 
                    ) 
                } 
            } 
            return count 
        } 
```

`Todo`选择操作：

```kt
         ... 
        override fun select(args: Pair<String, String>): List<Todo> =  
        select(listOf(args)) 

        override fun select(args: Collection<Pair<String, String>>):
         List<Todo> { 
            val items = mutableListOf<Todo>() 
            val selection = StringBuilder() 
            val selectionArgs = mutableListOf<String>() 
            args.forEach { arg -> 
                selection.append("${arg.first} == ?") 
                selectionArgs.add(arg.second) 
            } 
            val ctx = Journaler.ctx 
            ctx?.let { 
                val uri = Uri.parse(JournalerProvider.URL_TODOS) 
                val cursor = ctx.contentResolver.query( 
                        uri, null, selection.toString(),
                        selectionArgs.toTypedArray(), null 
                ) 
                while (cursor.moveToNext()) { 
                    val id = cursor.getLong
                   (cursor.getColumnIndexOrThrow(DbHelper.ID)) 
                    val titleIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_TITLE) 
                    val 
                    title = 
                    cursor.getString(titleIdx) 
                    val messageIdx = cursor.getColumnIndexOrThrow
                    (DbHelper.COLUMN_MESSAGE) 
                    val message = cursor.getString(messageIdx) 
                    val locationIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_LOCATION) 
                    val locationJson = cursor.getString(locationIdx) 
                    val location = gson.fromJson<Location>
                    (locationJson) 
                    val scheduledForIdx = cursor.getColumnIndexOrThrow( 
                        DbHelper.COLUMN_SCHEDULED 
                    ) 
                    val scheduledFor = cursor.getLong(scheduledForIdx) 
                    val todo = Todo(title, message, location,
                    scheduledFor) 
                    todo.id = id 
                    items.add(todo) 
                } 
                cursor.close() 
            } 
            return items 
        } 

        override fun selectAll(): List<Todo> { 
            val items = mutableListOf<Todo>() 
            val ctx = Journaler.ctx 
            ctx?.let { 
                val uri = Uri.parse(JournalerProvider.URL_TODOS) 
                val cursor = ctx.contentResolver.query( 
                        uri, null, null, null, null 
                ) 
                while (cursor.moveToNext()) { 
                    val id = cursor.getLong
                   (cursor.getColumnIndexOrThrow(DbHelper.ID)) 
                    val titleIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_TITLE) 
                    val title = cursor.getString(titleIdx) 
                    val messageIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_MESSAGE) 
                    val message = cursor.getString(messageIdx) 
                    val locationIdx = cursor.getColumnIndexOrThrow
                   (DbHelper.COLUMN_LOCATION) 
                    val locationJson = cursor.getString(locationIdx) 
                    val location = gson.fromJson<Location>
                    (locationJson) 
                    val scheduledForIdx = cursor.getColumnIndexOrThrow( 
                        DbHelper.COLUMN_SCHEDULED 
                    ) 
                    val scheduledFor = cursor.getLong(scheduledForIdx) 
                    val todo = Todo
                    (title, message, location, scheduledFor) 
                    todo.id = id 
                    items.add(todo) 
                } 
                cursor.close() 
            } 
            return items 
         } 
      } 
   }  
```

仔细阅读代码。我们用内容提供者替换了直接的数据库访问。更新你的 UI 类以使用新的重构代码。如果你在做这个过程中遇到困难，你可以看一下包含这些更改的 GitHub 分支：

[`github.com/PacktPublishing/-Mastering-Android-Development-with-Kotlin/tree/examples/chapter_12`](https://github.com/PacktPublishing/-Mastering-Android-Development-with-Kotlin/tree/examples/chapter_12)。

该分支还包含了 Journaler 内容提供程序客户端应用程序的示例。我们将突出显示客户端应用程序主屏幕上包含四个按钮的使用示例。每个按钮触发一个 CRUD 操作的示例，如下所示：

```kt
    package com.journaler.content_provider_client 

    import android.content.ContentValues 
    import android.location.Location 
    import android.net.Uri 
    import android.os.AsyncTask 
    import android.os.Bundle 
    import android.support.v7.app.AppCompatActivity 
    import android.util.Log 
    import com.github.salomonbrys.kotson.fromJson 
    import com.google.gson.Gson 
    import kotlinx.android.synthetic.main.activity_main.* 

   class MainActivity : AppCompatActivity() { 

     private val gson = Gson() 
     private val tag = "Main activity" 

     override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        setContentView(R.layout.activity_main) 

        select.setOnClickListener { 
            val task = object : AsyncTask<Unit, Unit, Unit>() { 
                override fun doInBackground(vararg p0: Unit?) { 
                    val selection = StringBuilder() 
                    val selectionArgs = mutableListOf<String>() 
                    val uri = Uri.parse
                    ("content://com.journaler.provider/notes") 
                    val cursor = contentResolver.query( 
                            uri, null, selection.toString(),
                            selectionArgs.toTypedArray(), null 
                    ) 
                    while (cursor.moveToNext()) { 
                        val id = cursor.getLong
                        (cursor.getColumnIndexOrThrow("_id")) 
                        val titleIdx =  cursor.
                        getColumnIndexOrThrow("title") 
                        val title = cursor.getString(titleIdx) 
                        val messageIdx = cursor.
                        getColumnIndexOrThrow("message") 
                        val message = cursor.getString(messageIdx) 
                        val locationIdx = cursor.
                        getColumnIndexOrThrow("location") 
                        val locationJson = cursor.
                        getString(locationIdx) 
                        val location = 
                        gson.fromJson<Location>(locationJson) 
                        Log.v( 
                                tag, 
                                "Note retrieved via content provider [
                                 $id, $title, $message, $location ]" 
                        ) 
                    } 
                    cursor.close() 
                } 
            } 
            task.execute() 
        } 

        insert.setOnClickListener { 
            val task = object : AsyncTask<Unit, Unit, Unit>() { 
                override fun doInBackground(vararg p0: Unit?) { 
                    for (x in 0..5) { 
                        val uri = Uri.parse
                       ("content://com.journaler.provider/note") 
                        val values = ContentValues() 
                        values.put("title", "Title $x") 
                        values.put("message", "Message $x") 
                        val location = Location("stub location $x") 
                        location.latitude = x.toDouble() 
                        location.longitude = x.toDouble() 
                        values.put("location", gson.toJson(location)) 
                        if (contentResolver.insert(uri, values) !=
                        null) { 
                            Log.v( 
                                    tag, 
                                    "Note inserted [ $x ]" 
                            ) 
                        } else { 
                            Log.e( 
                                    tag, 
                                    "Note not inserted [ $x ]" 
                            ) 
                        } 
                    } 
                } 
            } 
            task.execute() 
        } 

        update.setOnClickListener { 
            val task = object : AsyncTask<Unit, Unit, Unit>() { 
                override fun doInBackground(vararg p0: Unit?) { 
                    val selection = StringBuilder() 
                    val selectionArgs = mutableListOf<String>() 
                    val uri =
                    Uri.parse("content://com.journaler.provider/notes") 
                    val cursor = contentResolver.query( 
                            uri, null, selection.toString(),
                           selectionArgs.toTypedArray(), null 
                    ) 
                    while (cursor.moveToNext()) { 
                        val values = ContentValues() 
                        val id = cursor.getLong
                        (cursor.getColumnIndexOrThrow("_id")) 
                        val titleIdx =
                        cursor.getColumnIndexOrThrow("title") 
                        val title = "${cursor.getString(titleIdx)} upd:
                        ${System.currentTimeMillis()}" 
                        val messageIdx =
                       cursor.getColumnIndexOrThrow("message") 
                        val message = 
                       "${cursor.getString(messageIdx)} upd:
                       ${System.currentTimeMillis()}" 
                        val locationIdx = 
                       cursor.getColumnIndexOrThrow("location") 
                        val locationJson =
                       cursor.getString(locationIdx) 
                        values.put("_id", id) 
                        values.put("title", title) 
                        values.put("message", message) 
                        values.put("location", locationJson) 

                        val updated = contentResolver.update( 
                                uri, values, "_id = ?",
                                arrayOf(id.toString()) 
                        ) 
                        if (updated > 0) { 
                            Log.v( 
                                    tag, 
                                    "Notes updated [ $updated ]" 
                            ) 
                        } else { 
                            Log.e( 
                                    tag, 
                                    "Notes not updated" 
                            ) 
                        } 
                    } 
                    cursor.close() 
                } 
            } 
            task.execute() 
        } 

        delete.setOnClickListener { 
            val task = object : AsyncTask<Unit, Unit, Unit>() { 
                override fun doInBackground(vararg p0: Unit?) { 
                    val selection = StringBuilder() 
                    val selectionArgs = mutableListOf<String>() 
                    val uri = Uri.parse
                   ("content://com.journaler.provider/notes") 
                    val cursor = contentResolver.query( 
                            uri, null, selection.toString(),
                            selectionArgs.toTypedArray(), null 
                    ) 
                    while (cursor.moveToNext()) { 
                        val id = cursor.getLong
                        (cursor.getColumnIndexOrThrow("_id")) 
                        val deleted = contentResolver.delete( 
                                uri, "_id = ?", arrayOf(id.toString()) 
                        ) 
                        if (deleted > 0) { 
                            Log.v( 
                                    tag, 
                                    "Notes deleted [ $deleted ]" 
                            ) 
                        } else { 
                            Log.e( 
                                    tag, 
                                    "Notes not deleted" 
                            ) 
                        } 
                    } 
                    cursor.close() 
                } 

           } 
            task.execute() 
        } 
      } 
   } 
```

此示例演示了如何使用内容提供程序从其他应用程序触发 CRUD 操作。

# Android 适配器

为了在我们的主屏幕上呈现内容，我们将使用 Android Adapter 类。Android 框架提供了适配器作为一种机制，以将项目提供给视图组，如列表或网格。为了展示适配器的使用示例，我们将定义我们自己的适配器实现。创建一个名为`adapter`的新包和一个扩展`BaseAdapter`类的`EntryAdapter`成员类：

```kt
    package com.journaler.adapter 

    import android.annotation.SuppressLint 
    import android.content.Context 
    import android.view.LayoutInflater 
    import android.view.View 
    import android.view.ViewGroup 
    import android.widget.BaseAdapter 
    import android.widget.TextView 
    import com.journaler.R 
    import com.journaler.model.Entry 

    class EntryAdapter( 
        private val ctx: Context, 
        private val items: List<Entry> 
    ) : BaseAdapter() { 

    @SuppressLint("InflateParams", "ViewHolder") 
    override fun getView(p0: Int, p1: View?, p2: ViewGroup?): View { 
        p1?.let { 
            return p1 
        } 
        val inflater = LayoutInflater.from(ctx) 
        val view = inflater.inflate(R.layout.adapter_entry, null) 
        val label = view.findViewById<TextView>(R.id.title) 
        label.text = items[p0].title 
        return view 
    } 

    override fun getItem(p0: Int): Entry = items[p0] 
    override fun getItemId(p0: Int): Long = items[p0].id 
    override fun getCount(): Int = items.size 
   } 
```

我们重写了以下方法：

+   `getView()`: 根据容器中的当前位置返回填充视图的实例

+   `getItem()`: 这将返回我们用来创建视图的项目实例；在我们的情况下，这是`Entry`类实例（`Note`或`Todo`）

+   `getItemId()`: 这将返回当前项目实例的 ID

+   `getCount()`: 返回项目的总数

我们将连接适配器和我们的 UI。打开`ItemsFragment`并更新其`onResume()`方法，以实例化适配器并将其分配给`ListView`，如下所示：

```kt
    override fun onResume() { 
        super.onResume() 
        ... 
        executor.execute { 
            val notes = Content.NOTE.selectAll() 
            val adapter = EntryAdapter(activity, notes) 
            activity.runOnUiThread { 
                view?.findViewById<ListView>(R.id.items)?.adapter =
             adapter 
            } 
        } 
    } 
```

当您构建和运行应用程序时，您应该看到`ViewPager`的每个页面都填充了加载的项目，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/1fdfdd42-d4ba-4f48-b569-5da14b86d4f2.png)

# 内容加载器

内容加载器为您提供了一种机制，用于从内容提供程序或其他数据源加载数据，以在 UI 组件（如 Activity 或 Fragment）中显示。这些是加载程序提供的好处：

+   在单独的线程上运行

+   通过提供回调方法简化线程管理

+   加载程序在配置更改期间保持和缓存结果，从而防止重复查询

+   我们可以实现并成为监视数据更改的观察者

我们将创建我们的内容加载器实现。首先，我们需要更新`Adapter`类。由于我们将处理游标，我们将使用`CursorAdapter`而不是`BaseAdapter`。`CursorAdapter`在主构造函数中接受`Cursor`实例作为参数。`CursorAdapter`的实现比我们现在拥有的要简单得多。打开`EntryAdapter`并更新如下：

```kt
    class EntryAdapter(ctx: Context, crsr: Cursor) : CursorAdapter(ctx,
    crsr) { 

    override fun newView(p0: Context?, p1: Cursor?, p2: ViewGroup?):
    View { 
        val inflater = LayoutInflater.from(p0) 
        return inflater.inflate(R.layout.adapter_entry, null) 
    } 

    override fun bindView(p0: View?, p1: Context?, p2: Cursor?) { 
        p0?.let { 
            val label = p0.findViewById<TextView>(R.id.title) 
            label.text = cursor.getString( 
                cursor.getColumnIndexOrThrow(DbHelper.COLUMN_TITLE) 
            ) 
        } 
    } 

   } 
```

我们有以下两种要重写的方法：

+   `newView()`: 这将返回要填充数据的视图的实例

+   `bindView()`: 这将填充来自`Cursor`实例的数据

最后，让我们更新我们的`ItemsFragment`类，以便使用内容加载器实现：

```kt
    class ItemsFragment : BaseFragment() { 
      ... 
      private var adapter: EntryAdapter? = null 
      ... 
      private val loaderCallback = object :
      LoaderManager.LoaderCallbacks<Cursor> { 
        override fun onLoadFinished(loader: Loader<Cursor>?, cursor:
        Cursor?) { 
            cursor?.let { 
                if (adapter == null) { 
                    adapter = EntryAdapter(activity, cursor) 
                    items.adapter = adapter 
                } else { 
                    adapter?.swapCursor(cursor) 
                } 
            } 
        } 

        override fun onLoaderReset(loader: Loader<Cursor>?) { 
            adapter?.swapCursor(null) 
        } 

        override fun onCreateLoader(id: Int, args: Bundle?):
        Loader<Cursor> { 
            return CursorLoader( 
                    activity, 
                    Uri.parse(JournalerProvider.URL_NOTES), 
                    null, 
                    null, 
                    null, 
                    null 
            ) 
        } 
    } 

    override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        loaderManager.initLoader( 
                0, null, loaderCallback 
        ) 
    } 

    override fun onResume() { 
        super.onResume() 
        loaderManager.restartLoader(0, null, loaderCallback) 

        val btn = view?.findViewById
       <FloatingActionButton>(R.id.new_item) 
        btn?.let { 
            animate(btn, false) 
        } 
    } 
   }  
```

我们通过调用 Fragment 的`LoaderManager`成员来初始化`LoaderManager`。我们执行的两个关键方法如下：

+   `initLoader()`: 这确保加载程序已初始化并处于活动状态

+   `restartLoader()`: 这将启动新的或重新启动现有的`loader`实例

这两种方法都接受 loader ID 和 bundle 数据作为参数，并提供了要重写的`LoaderCallbacks<Cursor>`实现，其中包括以下三种方法：

+   `onCreateLoader()`: 为我们提供的 ID 实例化并返回一个新的加载程序实例

+   `onLoadFinished()`: 当先前创建的 loader 完成加载时调用

+   `onLoaderReset()`: 当先前创建的 loader 正在被重置时调用，因此使其数据不可用

# 数据绑定

Android 支持一种数据绑定机制，以便将数据与视图绑定，并最小化粘合代码。通过更新您的构建 Gradle 配置来启用数据绑定，如下所示：

```kt
     android { 
       .... 
       dataBinding { 
        enabled = true 
       } 
     } 
     ... 
     dependencies { 
      ... 
      kapt 'com.android.databinding:compiler:2.3.1' 
    } 
    ...  
```

现在，您可以定义绑定表达式。看一下以下示例：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <layout > 

    <data> 
        <variable 
            name="note" 
            type="com.journaler.model.Note" /> 
    </data> 

    <LinearLayout 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:orientation="vertical"> 

        <TextView 
            android:layout_width="wrap_content" 
            android:layout_height="wrap_content" 
            android:text="@{note.title}" /> 

    </LinearLayout> 
  </layout>  
```

让我们按照以下方式绑定数据：

```kt
    package com.journaler.activity 

    import android.databinding.DataBindingUtil 
    import android.location.Location 
    import android.os.Bundle 
    import com.journaler.R 
    import com.journaler.databinding.ActivityBindingBinding 
    import com.journaler.model.Note 

    abstract class BindingActivity : BaseActivity() { 

    override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        /** 
         * ActivityBindingBinding is auto generated class 
         * which name is derived from activity_binding.xml filename. 
         */ 
        val binding : ActivityBindingBinding =
        DataBindingUtil.setContentView( 
            this, R.layout.activity_binding 
        ) 
        val location = Location("dummy") 
        val note = Note("my note", "bla", location) 
        binding.note = note 
      } 

    }  
```

就是这样！看看将数据绑定到布局视图是多么简单！我们强烈建议您尽可能多地使用数据绑定。创建您自己的示例！随意尝试！

# 使用列表

我们向您展示了如何处理数据。正如您注意到的，在主视图数据容器中，我们使用了`ListView`。为什么我们选择它？首先，它是最常用的容器来保存您的数据。在大多数情况下，您将使用`ListView`来保存来自适配器的数据。永远不要在可滚动容器（如`LinearLayout`）中放置大量视图！尽可能使用`ListView`。当不再需要视图时，它会回收视图，并在需要时重新实例化它们。

使用列表可能会影响您的应用程序性能，因为它是一个用于显示数据的优化良好的容器。显示列表是几乎任何应用程序的基本功能！任何生成一组数据作为某些操作结果的应用程序都需要一个列表。在您的应用程序中几乎不可能不使用它。

# 使用网格

我们注意到列表的重要性。但是，如果我们计划将数据呈现为网格呢？对我们来说太幸运了！Android 框架为我们提供了一个与`ListView`非常相似的`GridView`。您在布局中定义您的`GridView`，并将适配器实例分配给`GridView`的适配器属性。`GridView`将为您回收所有视图，并在需要时执行实例化。列表和网格之间的主要区别在于您必须为您的`GridView`定义列数。以下示例将向您展示`GridView`的使用示例：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
   <GridView  
      android:id="@+id/my_grid" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:columnWidth="100dp" 
      android:numColumns="3" 
      android:verticalSpacing="20dp" 
      android:horizontalSpacing="20dp" 

      android:stretchMode="columnWidth" 
      android:gravity="center" 
    /> 
```

我们将突出显示我们在此示例中使用的重要属性：

+   `columnWidth`：指定每列的宽度

+   `numColumns`：指定列数

+   `verticalSpacing`：指定行之间的垂直间距

+   `horizontalSpacing`：指定网格中项目之间的水平间距

尝试将当前应用程序的主`ListView`更新为以`GridView`形式呈现数据。调整它，使其对最终用户看起来愉悦。再次，随意尝试实验！

# 实现拖放

在本章的最后一节，我们将向您展示如何实现拖放功能。这是您在大多数包含列表数据的应用程序中可能需要的功能。使用列表并不是执行拖放的必要条件，因为您可以拖动任何（视图）并将其释放到定义了适当监听器的任何位置。为了更好地理解我们所讨论的内容，我们将向您展示一个实现的例子。

让我们定义一个视图。在该视图上，我们将设置一个长按监听器，触发拖放操作：

```kt
    view.setOnLongClickListener { 
            val data = ClipData.newPlainText("", "") 
            val shadowBuilder = View.DragShadowBuilder(view) 
            view.startDrag(data, shadowBuilder, view, 0) 
            true 
   } 
```

我们使用`ClipData`类来传递数据以放置目标。我们定义了`dragListener`，并将其分配给我们期望它放置的视图：

```kt
    private val dragListener = View.OnDragListener { 
        view, event -> 
        val tag = "Drag and drop" 
        event?.let { 
            when (event.action) { 
                DragEvent.ACTION_DRAG_STARTED -> { 
                    Log.d(tag, "ACTION_DRAG_STARTED") 
                } 
                DragEvent.ACTION_DRAG_ENDED -> { 
                    Log.d(tag, "ACTION_DRAG_ENDED") 
                } 
                DragEvent.ACTION_DRAG_ENTERED -> { 
                    Log.d(tag, "ACTION_DRAG_ENDED") 
                } 
                DragEvent.ACTION_DRAG_EXITED -> { 
                    Log.d(tag, "ACTION_DRAG_ENDED") 
                } 
                else -> { 
                    Log.d(tag, "ACTION_DRAG_ ELSE ...") 
                } 
            } 
        } 
        true 
     } 

    target?.setOnDragListener(dragListener) 
```

拖放监听器将在我们开始拖动视图并最终释放到具有分配的监听器的`target`视图上时触发代码。

# 总结

在本章中，我们涵盖了许多主题。我们学习了关于后端通信，如何使用 Retrofit 与后端远程实例建立通信，以及如何处理我们获取的数据。本章的目的是使用内容提供程序和内容加载器。我们希望您意识到它们的重要性以及它们的好处。最后，我们演示了数据绑定；注意到我们的数据视图容器的重要性，比如`ListView`和`GridView`；并向您展示了如何执行拖放操作。在下一章中，我们将开始测试我们的代码。准备好进行性能优化，因为这是我们下一章要做的事情！
