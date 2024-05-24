# 通过构建安卓应用学习 Kotlin（三）

> 原文：[`zh.annas-archive.org/md5/201D65C8BC4C6A97336C0B7173DD6D6D`](https://zh.annas-archive.org/md5/201D65C8BC4C6A97336C0B7173DD6D6D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：为任务设置提醒

在许多现实世界的应用程序中，有必要在某个时候提醒用户，比如说，采取一些行动或提供一些信息。例如，健身应用程序可能会提醒用户开始一些锻炼课程。

在这里，您将通过为任务设置提醒，然后在提醒到期时弹出通知，来构建上一章中的 ToDoList 应用程序。在实现这些功能时，您将学到很多，使用诸如`IntentService`、`BroadcastReceiver`和`Notification`等类。

在本章中，您将创建一个允许用户为任务设置提醒的功能。

在本章结束时，您将学到以下内容：

+   为设置的提醒创建和显示通知

+   推送通知简介

+   如何使用云服务（如 Firebase 和 Amazon SNS）发送推送通知，以及

+   如何设置您的应用程序以接收和显示推送通知给用户

总的来说，本章涵盖的主题包括：

+   服务

+   广播接收器

+   应用内通知

+   推送通知

# AlarmManager

Android 中的提醒最好通过使用`AlarmManager`来实现。为什么？看看官方文档对此的解释：

*这些允许您安排应用程序在将来的某个时间运行。*

另外：

*闹钟管理器适用于您希望在特定时间运行应用程序代码的情况，即使您的应用程序当前未运行。对于正常的定时操作（滴答声、超时等），使用 Handler 更容易、更有效率。*

这意味着如果您想要实现提醒这样的功能，您来对地方了。用于处理这种任务的替代类`Handler`最适合在应用程序仍在使用时完成的任务。您的应用程序肯定会有跨天的提醒，可能会持续几周甚至几个月，因此最好使用`AlarmManager`类。

它的工作原理是这样的，您的应用程序将启动一个后台服务来启动提醒的计时器，然后在到期时向应用程序发送广播。继续看如何实现这一点。

# 创建闹钟

基本上，有四种类型的闹钟：

+   **经过的实时：**这会根据设备启动以来经过的时间触发挂起的意图，但不会唤醒设备。经过的时间包括设备休眠期间的任何时间。

+   **经过的实时唤醒：**这会唤醒设备，并在自设备启动以来经过的指定时间后触发挂起的意图。

+   **RTC：**这在指定时间触发挂起的意图，但不会唤醒设备。

+   **RTC 唤醒：**这会唤醒设备，以便在指定时间触发挂起的意图。

您将使用 RTC 唤醒闹钟类型来唤醒设备，在用户设置的精确时间触发闹钟。

首先，为用户选择闹钟应该响起的时间创建一个对话框。创建一个名为`TimePickerFragment`的新类。然后，使用此处显示的代码进行更新：

```kt
import android.app.AlarmManager
import android.app.Dialog
import android.app.PendingIntent
import android.app.TimePickerDialog
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.support.v4.app.DialogFragment
import android.text.format.DateFormat
import android.util.Log
import android.widget.TimePicker
import android.widget.Toast
import java.util.Calendar

class TimePickerFragment : DialogFragment(), TimePickerDialog.OnTimeSetListener {

 override fun onCreateDialog(savedInstanceState: Bundle): Dialog {
 val c = Calendar.getInstance()
 val hour = c.get(Calendar.HOUR_OF_DAY)
 val minute = c.get(Calendar.MINUTE)

 return TimePickerDialog(activity, this, hour, minute,
 DateFormat.is24HourFormat(activity))
 }

 override fun onTimeSet(view: TimePicker, hourOfDay: Int, minute: Int) {
        Log.d("onTimeSet", "hourOfDay: $hourOfDay minute:$minute")

        Toast.makeText(activity, "Reminder set successfully", Toast.LENGTH_LONG).show()

        val intent = Intent(activity, AlarmReceiver::class.java)
        intent.putExtra(ARG_TASK_DESCRIPTION, taskDescription)

        val alarmIntent = PendingIntent.getBroadcast(activity, 0, intent, 0)
        val alarmMgr = activity.getSystemService(Context.ALARM_SERVICE) as AlarmManager

        val calendar = Calendar.getInstance()
        calendar.set(Calendar.HOUR_OF_DAY, hourOfDay)
        calendar.set(Calendar.MINUTE, minute)

        alarmMgr.set(AlarmManager.RTC_WAKEUP, calendar.timeInMillis, alarmIntent)
    }
}

companion object {
     val ARG_TASK_DESCRIPTION = "task-description"

    fun newInstance(taskDescription: String): TimePickerFragment {
        val fragment = TimePickerFragment()
        val args = Bundle()
        args.putString(ARG_TASK_DESCRIPTION, taskDescription)
        fragment.arguments = args
        return fragment
    }
}
```

在`onCreateDialog`方法中，您创建了一个`TimePickerDialog`的实例，并将默认时间设置为当前时间。因此，当时间选择器启动时，它将显示当前时间。

然后，您重写了`onTimeSet`方法来处理用户设置的时间。您首先记录了时间，然后显示了一个提示，说明时间已成功设置并记录。

然后，您创建了一个意图来执行`AlarmReceiver`（您很快将创建它）。接下来是一个`PendingIntent`，在闹钟响起时触发。然后，您（终于）创建了传入用户时间的闹钟。这个闹钟将在用户设置的确切时间触发。而且，它只会运行一次。

# 启动提醒对话框

打开`MainActivity`文件，进行一些快速更新，以便您可以显示对话框。

在`onCreateOptionsMenu`中，进行以下更改：

```kt
override fun onCreateOptionsMenu(menu: Menu): Boolean {
    ...
    val reminderItem = menu.findItem(R.id.reminder_item)

    if (showMenuItems) {
        ...
        reminderItem.isVisible = true
    }

    return true
}
```

你刚刚添加了一个提醒菜单项，当用户点击任务时会显示。现在，转到`onOptionsItemSelected`，以便在选择此菜单项时启动时间选择器。使用以下代码来实现：

```kt
} else if (R.id.delete_item == item?.itemId) {
    ...
} else if (R.id.reminder_item == item?.itemId) {
    TimePickerFragment.newInstance("Time picker argument")
            .show(fragmentManager, "MainActivity")
}
```

接下来，使用以下代码更新`to_do_list_menu.xml`中的菜单项：

```kt
<item
    android:id="@+id/reminder_item"
    android:title="@string/reminder"
    android:icon="@android:drawable/ic_menu_agenda"
    android:visible="false"
    app:showAsAction="ifRoom"/>
```

现在，使用以下代码在你的`strings.xml`文件中添加`"reminder"`字符串资源：

```kt
<resources>
    ...
    <string name="reminder">Reminder</string>
</resources>
```

好的，做得很好。现在，记得上面的`AlarmReceiver`类吗？它是做什么的？继续了解一下。

# BroadcastReceiver

这是你学习`BroadcastReceiver`类的地方。根据官方文档，它是接收和处理由`sendBroadcast(Intent)`发送的广播意图的代码的基类。

基本上，它负责在你的应用中接收广播事件。有两种注册这个接收器的方法：

+   动态地，使用`Context.registerReceiver()`的这个类的实例，或者

+   静态地，使用 AndroidManifest.xml 中的`<receiver>`标签

文档中的一个重要说明：

*从 Android 8.0（API 级别 26）开始，系统对在清单中声明的接收器施加了额外的限制。如果你的应用目标是 API 级别 26 或更高，你不能使用清单来声明大多数隐式广播的接收器（不特定地针对你的应用）。*

# 发送广播

你将使用`LocalBroadcastManager`在闹钟响起时向用户发送通知。这是文档中的一个提示，说明为什么最好使用这种广播方法：

*“如果你不需要跨应用发送广播，请使用本地广播。实现方式更加高效（不需要进程间通信），而且你不需要担心其他应用能够接收或发送你的广播所涉及的任何安全问题。”*

而且，这告诉我们为什么它是高效的：

*本地广播可以作为应用中的通用发布/订阅事件总线使用，而不需要系统范围广播的任何开销。*

# 创建广播接收器

创建一个新文件并命名为`AlarmReceiver`，让它扩展`BroadcastReceiver`。然后，使用以下代码更新它：

```kt
class AlarmReceiver: BroadcastReceiver() {

    override fun onReceive(context: Context?, p1: Intent?) {
        Log.d("onReceive", "p1$p1")
        val i = Intent(context, AlarmService::class.java)
        context?.startService(i)
    }
}
```

你所做的只是重写`onReceive`方法来启动名为`AlarmService`的`IntentService`（这个类将负责显示通知）。嗯，日志语句只是为了帮助调试。

在继续之前，在你的`AndroidManifest.xml`中注册服务，就像`MainActivity`组件一样。在这里，你只需要`name`属性：

```kt
<application>
    ...
  <service android:name=".AlarmReceiver"/>
</application>
```

现在，继续创建由`AlarmReceiver`启动的`AlarmService`。

# 创建 AlarmService

**IntentService**

首先听听官方文档的说法：

“`IntentService`是处理异步请求（表示为 Intents）的`Services`的基类。客户端通过`startService(Intent)`调用发送请求；服务根据需要启动，使用工作线程依次处理每个 Intent，并在工作完成时停止自身。”

`IntentService`是一个通过`Intents`处理请求的`Service`组件。接收到`Intent`后，它会启动一个工作线程来运行任务，并在工作完成时停止，或者在适当的时候停止。

关键之处在于它赋予你的应用在没有任何干扰的情况下执行一些工作的能力。这与`Activity`组件不同，例如，后者必须在前台才能运行任务。`AsyncTasks`可以帮助解决这个问题，但仍然不够灵活，对于这样一个长时间运行的任务来说并不合适。继续看它的实际应用。

**注意：**

+   `IntentService`有自己的单个工作线程来处理请求

+   一次只处理一个请求

# 创建一个 IntentService

创建`IntentService`的子类称为`ReminderService`。您将需要重写`onHandleIntent()`方法来处理`Intent`。然后，您将构建一个`Notification`实例来通知用户提醒已到期：

```kt
import android.app.IntentService
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.support.v4.app.NotificationCompat
import android.util.Log

class AlarmService : IntentService("ToDoListAppAlarmReceiver") {
 private var context: Context? = null

 override fun onCreate() {
 super.onCreate()
 context = applicationContext
 }

 override fun onHandleIntent(intent: Intent?) {
 intent?showNotification(it)

 if(null == intent){
 Log.d("AlarmService", "onHandleIntent( OH How? )")
 }
 }

 private fun showNotification(taskDescription: String) {
 Log.d("AlarmService", "showNotification($taskDescription)")
 val CHANNEL_ID = "todolist_alarm_channel_01"
 val mBuilder = NotificationCompat.Builder(this, CHANNEL_ID)
 .setSmallIcon(R.drawable.ic_notifications_active_black_48dp)
 .setContentTitle("Time Up!")
 .setContentText(taskDescription)

 val mNotificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
 mNotificationManager.notify(23, mBuilder.build())
 }
}
```

通过代码步骤，这就是您刚刚做的事情：

在`onCreate()`中，您保存了`applicationContext`的一个实例以供以后使用。

在`onHandleIntent()`中，您使用了 Kotlin 安全检查功能来确保在非空实例上调用`showNotification()`方法。

在`showNotification()`中，您使用`NotificationCompat`构建器创建了一个通知实例。您还设置了通知的标题和内容。然后，使用`NotificationManager`，您触发了通知。`notify()`方法中的 ID 参数是唯一标识您的应用程序的此通知的标识。

您也需要注册服务。以下是如何操作：

```kt
<service android:name=".AlarmService"
         android:exported="false"/>

```

您应该熟悉这一点，除了`android:exported`。这只是意味着我们不允许任何外部应用程序与此服务进行交互。

以下是关于`IntentService`类的一些重要限制。

+   它无法直接与您的用户界面交互。要将其结果放入 UI，您必须将它们发送到 Activity。

+   工作请求按顺序运行。如果`IntentService`中正在运行操作，并且您发送另一个请求，则该请求将等待，直到第一个操作完成。

+   在`IntentService`上运行的操作无法被中断。

现在是运行您的应用程序的时候了。闹钟应该会响起，您应该会看到通知指示。

还有其他发送通知到您的应用程序的方法。继续阅读以了解有关推送通知的信息。

# Firebase Cloud Messaging

"Firebase Cloud Messaging（FCM）是一个跨平台的消息传递解决方案，可以让您免费可靠地传递消息。"我相信这是对这项服务的最好简要描述。实际上，它实际上是谷歌创建和运行的 Firebase 平台上许多其他服务套件的一部分。

您已经集成了应用内通知，现在您将看到如何使用 FCM 实现推送通知。

应用内通知基本上意味着通知是由应用程序内部触发和发送的。另一方面，推送通知是由外部来源发送的。

# 集成 FCM

1.  设置 FCM SDK

您首先必须将**SDK**（软件开发工具包）添加到您的应用程序中。您应该确保您的目标至少是 Android 4.0（冰淇淋三明治）。它应该安装有 Google Play 商店应用程序，或者运行 Android 4.0 和 Google API 的模拟器。您的 Android Studio 版本应至少为 2.2。您将在 Android Studio 中使用 Firebase 助手窗口进行集成。

还要确保您已安装了 Google 存储库版本 26 或更高版本，方法如下：

1.  单击**工具**|**Android**|**SDK 管理器**

1.  单击**SDK 工具**选项卡

1.  检查**Google 存储库**复选框，然后单击**确定**

1.  单击**确定**进行安装

1.  单击**后台**以在后台完成安装，或者等待安装完成后单击**完成**

现在，您可以按照以下步骤在 Android Studio 中打开并使用**助手**窗口：

1.  单击**工具**|**Firebase**打开**助手**窗口：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6a103bf5-54c6-4953-bb1e-7fb70d374d00.png)

1.  单击展开并选择 Cloud Messaging，然后单击**设置 Firebase Cloud Messaging**教程以连接到 Firebase 并向您的应用程序添加必要的代码：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c7568e23-bace-4d3a-9697-159c82d508d0.png)

助手的外观如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/25b92672-0964-4447-8cdb-5d4286a39680.png)

如果您成功完成了 Firebase 助手的操作指南，您将完成以下操作：

+   在 Firebase 上注册您的应用程序

+   通过对根级`build.gradle`文件进行以下更新，将 SDK 添加到您的应用程序

```kt
buildscript {
    // ...
    dependencies {
        // ...
        classpath 'com.google.gms:google-services:3.1.1' // google-services plugin
    }
}

allprojects {
    // ...
    repositories {
        // ...
        maven {
            url "https://maven.google.com" // Google's Maven repository
        }
    }
}
```

然后，在您模块的`build.gradle`文件中，它将在文件底部添加`apply plugin`行，如下所示：

```kt
apply plugin: 'com.android.application'

android {
  // ...
}
dependencies {
  // ...
  compile 'com.google.firebase:firebase-core:11.8.0'
}
// ADD THIS AT THE BOTTOM
apply plugin: 'com.google.gms.google-services'
```

使用以下内容更新您的清单：

```kt
<service
    android:name=".MyFirebaseMessagingService">
    <intent-filter>
        <action android:name="com.google.firebase.MESSAGING_EVENT"/>
    </intent-filter>
</service>
```

如果您想在应用程序运行时手动处理从 FCM 接收到的消息，则需要这样做。但是，由于现在有一种方法可以在没有您干预的情况下显示通知，因此您现在不需要这样做。

对于该功能，您需要以下内容：

```kt
<service
    android:name=".MyFirebaseInstanceIDService">
    <intent-filter>
        <action android:name="com.google.firebase.INSTANCE_ID_EVENT"/>
    </intent-filter>
</service>
```

现在，您将创建`MyFirebaseInstanceIDService`类以扩展`FirebaseInstanceIdService`。

如果由于某种原因，这些步骤中的任何一个未完成，您可以手动登录到 Firebase 网站，并按照以下步骤创建 Firebase 上的项目并更新应用程序的构建文件。

使用 Firebase 网站，在登录后的第一件事是添加您的项目：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/914faa3a-4529-45b6-b103-f400d3bb3acd.png)

然后，您将被要求输入项目的名称。为**项目名称**输入**ToDoList**。它将自动生成一个全局唯一的**项目 ID**。然后，选择您的居住国家，并点击**创建项目**按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e4b145b2-7a66-4355-8d4f-0460f2d1b889.png)

之后，选择所需的平台。请注意，Firebase 不仅用于 Android，还用于 iOS 和 Web。因此，请选择**将 Firebase 添加到您的 Android 应用**选项：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a2c42a0d-1f87-4584-917b-dc01c619c669.png)

现在您将通过一个三步过程：

1.  第一步是通过提供您的包名称注册您的应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2d277a5f-f983-442e-950f-14ab98434a00.png)

1.  在此步骤中，您只需下载**google-services.json**文件：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e58c83cd-c1b9-46de-bf7c-d5110e6a68d2.png)

1.  然后，在最后一步中，您将向应用程序添加 SDK。请注意，如果您已经这样做，则无需此操作：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/16d7f695-9998-4fb9-a6dc-6f5a6b7c7927.png)

就是这样。您已经在 Firebase 上添加了您的应用程序。现在，您将看到新创建项目的页面。在这里，您将看到所有可用于您的应用程序的服务。选择**通知**服务，然后单击**开始**：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b4675cee-3c50-4ef6-b5be-65aed39271ba.png)

现在，您将看到以下页面。单击**发送您的第一条消息**按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/93d004bb-9bd4-446d-bfdc-8aaa227f0d75.png)

然后，选择**撰写消息**。在这里，输入要在**消息文本**框中发送的消息。选择**单个设备**作为目标。在输入**FCM 注册令牌**后，您将点击**发送消息**按钮以发送通知。继续阅读以了解如何获取注册令牌：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6bae15c3-2af4-4d1d-8c3f-c1e22308904d.png)

注册令牌

在设置 FCM 后首次运行应用程序时，FCM SDK 将为您的应用程序生成一个令牌。在以下情况下，此令牌将更改，并相应地生成一个新的令牌：

+   应用程序删除实例 ID

+   应用程序在新设备上恢复

+   用户卸载/重新安装应用程序

+   用户清除应用程序数据

此令牌必须保持私密。要访问此令牌，您将其记录到您的`Logcat`控制台中。首先，打开`MyFirebaseInstanceIDservice`并使用以下代码进行更新：

```kt
override fun onTokenRefresh() {
    // Get updated InstanceID token.
    val refreshedToken = FirebaseInstanceId.getInstance().getToken()
    Log.d(FragmentActivity.TAG, "Refreshed token: " + refreshedToken)

    // If you want to send messages to this application instance or
    // manage this apps subscriptions on the server side, send the
    // Instance ID token to your app server.
    sendRegistrationToServer(refreshedToken)
}
```

现在您已经有了密钥，请将其粘贴到上面的**撰写消息**框中，然后点击**发送消息**按钮。之后不久，您应该会在手机上看到通知。

# 摘要

在本章中，您学习了如何使用 Firebase 创建后台服务，发送广播消息，显示应用内通知和推送通知。有一些事情您可以自己做来加深对这些主题的理解： 

+   而不是使用某些静态消息通知用户，请使用设置提醒的任务的描述

+   使用 Firebase，您还可以尝试向一组人发送推送通知，而不是单个设备


# 第十三章：测试和持续集成

在本章中，您将了解**持续集成**（**CI**）的概念和测试的重要性。从未听说过 CI？那测试呢？

在本章中，我们将：

+   了解编写测试

+   了解 Android 测试支持库

+   学习如何使用 Crashlytics 来跟踪崩溃报告

+   了解 beta 测试

+   介绍 CI 的概念

+   了解 Jenkins、Bamboo 和 Fastlane 等工具以及如何将它们用于构建自动化和部署

# 测试

软件测试是评估软件或其部分以确保其按预期工作的过程。产品必须满足其构建的给定要求。因此，测试报告给出了软件质量的指示。测试的另一个主要原因是找到错误并修复它们。

有时，有诱惑将测试视为事后思考。这主要是由于时间限制等问题，但考虑到测试的重要性，它应该成为开发过程的一部分。在软件生命周期的后期编写测试可能是非常糟糕的经历。您可能不得不花费大量时间重构它，使其可测试，然后才能编写测试。所有这些因素涉及的挫折使大多数软件难以进行适当的测试。 

# 测试的重要性

测试是一个非常广泛的话题，你可以很容易地写一本书。测试的重要性无法过分强调。以下是一些软件需要测试的原因：

+   它使企业能够欣赏和理解软件实施的风险

+   它确保编写了质量程序

+   它有助于生产无 bug 的产品

+   它降低了维护成本

+   这是验证和验证软件的一种可靠方式

+   它提高了性能

+   它确认了所有声明的功能要求都已经实施

+   它给客户带来信心

+   它更快地暴露错误

+   这是为了保持业务的需要

+   它确保产品可以在其预期环境中安装和运行

# Android 测试支持库

**Android 测试支持库**（**ATSL**）是一组专门为测试 Android 应用程序而构建的库。它就像您在 Android 应用程序开发中使用的通常支持库一样，只是这个库是专门用于测试的。

# Model-View-Presenter 架构

如前所述，软件需要可测试。只有这样，我们才能为其编写有效的测试。因此，您将使用**Model-View-Presenter**（**MVP**）架构设计您的应用程序。这种架构采用了一些设计最佳实践，如控制反转和依赖注入，因此非常适合测试。为了使应用程序可测试，其各个部分必须尽可能解耦。

查看以下图表中 MVP 架构的高级图解：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4744851a-ccfd-4477-aec1-471e8558a85e.png)

非常简单地说，这些各部分的含义是：

+   Model：它提供并存储应用程序的数据

+   View：它处理模型数据的显示

+   Presenter：它协调 UI 和数据

您还可以轻松地替换其他部分并在测试期间模拟它们。在软件测试中，模拟是模仿真实对象的对象。您将提供其行为，而不是依赖于代码的实际实现。这样，您就可以专注于正在进行预期操作的测试类。您将在以下部分中看到它们的实际应用。

# 测试驱动开发

您将使用一种称为**测试驱动开发**（**TDD**）的软件开发类型构建一个 Notes 应用程序。看一下下面的图表和下面的解释：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/14fc8340-e928-4d1b-874f-ddb4f70c3e3b.png)

**TDD**是一种软件开发方法，其中测试是在实际程序代码之前编写的。

红：红是 TDD 过程的第一阶段。在这里，您编写测试。由于这是第一个测试，这意味着您基本上没有什么可以测试的。因此，您必须编写最少量的代码来进行测试。现在，由于这是编写测试所需的最少量代码，当您编写代码时它很可能会失败。但这完全没关系。在 TDD 中，您的测试必须在发生任何其他事情之前失败！当您的测试失败时，这是 TDD 周期的第一阶段-红色阶段。

绿色：现在，您必须编写通过测试所需的最少量代码。当测试通过时，那很好，您已经完成了 TDD 周期的第二阶段。通过测试意味着您的程序的一部分正如您期望的那样工作。随着您以这种方式构建应用程序，任何时候您都将测试代码的每个部分。您能看到这是如何运作的吗？当您完成一个功能时，您将有足够的测试来测试该功能的各个部分。

重构：TDD 过程的最后阶段是重构您早期编写的代码以通过测试。在这里，您删除冗余代码，清理代码，并为模拟编写完整的实现。之后再次运行测试。它们可能会失败。在 TDD 中，测试失败是件好事。当您编写测试并且它们通过时，您可以确信特定的需求或期望已经得到满足。

还有其他围绕测试构建的开发模型，例如行为驱动测试、黑盒测试和冒烟测试。但是，它们基本上可以归类为功能测试和非功能测试。

# 功能与非功能测试

通过功能测试，您将根据给定的业务需求测试应用程序。它们不需要应用程序完全运行。这些包括：

+   单元测试

+   集成测试

+   验收测试

对于非功能测试，您将测试应用程序与其操作环境的交互。例如，应用程序将连接到真实数据源并使用 HTTP 连接。这些包括：

+   安全测试

+   可用性测试

+   兼容性测试

# 笔记应用程序

要开始构建我们的笔记应用程序，请创建一个新应用程序并将其命名为 notes-app。使用 Android Studio 左上角的选项卡切换到项目视图。此视图允许您查看项目结构，就像它在文件系统上存在的那样。它应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2040b167-15e5-4220-975c-59cbb23f4ad1.png)

单元测试测试代码的小部分，而不涉及产品的其他部分。在这种情况下，这意味着您的单元测试不需要物理设备，也不需要 Android jar、数据库或网络；只需要您编写的源代码。这些是应该在`test`目录中编写的测试。

另一方面，集成测试包括运行应用程序所需的所有组件，这些测试将进入`androidTest`目录。

# 测试依赖项

目前，只有一个测试库`Junit`，您将用它进行单元测试。但是，由于您的代码将与其他组件交互，即使它们不是被测试的组件，您也必须对它们进行模拟。`Junit`仍然不足以编写测试用例。因此，您还需要添加`Hamcrest`来帮助创建断言匹配等。让我们继续添加我们需要的库。

打开模块的构建文件，更新依赖项以匹配以下代码，并同步项目：

```kt
dependencies {
  implementation fileTree(dir: 'libs', include: ['*.jar'])
  implementation "org.jetbrains.kotlin:kotlin-stdlib-jre7:$kotlin_version"
  implementation 'com.android.support:appcompat-v7:26.1.0'
  implementation 'com.android.support.constraint:constraint-layout:1.0.2'
  testImplementation 'junit:junit:4.12'
  testImplementation "org.mockito:mockito-all:1.10.19"
  testImplementation "org.hamcrest:hamcrest-all:1.3"
  testImplementation "org.powermock:powermock-module-junit4:1.6.2"
  testImplementation "org.powermock:powermock-api-mockito:1.6.2"
  androidTestImplementation 'com.android.support.test:runner:1.0.1'
  androidTestImplementation 'com.android.support.test.espresso:espresso-core:3.0.1'
}
```

目前，请使用与前面代码中显示的确切库版本相同的库版本。这意味着您将不得不忽略 IDE 提升库版本的建议。

稍后，您可以更新为彼此兼容的较新稳定版本。

# 您的第一个测试

您将首先开始向用户显示笔记。笔记演示者将提供显示进度指示器的逻辑，显示笔记和其他与笔记相关的视图。

由于**Presenter**在**Model**和**View**之间协调，因此您必须对它们进行模拟，以便您可以专注于正在测试的类。

在这个测试中，您将验证要求`NotesPresenter`添加新笔记将触发调用`View`来显示添加笔记屏幕。让我们实现`should display note when button is clicked`测试方法。

首先，您将添加对 presenter 的`addNewNote()`方法的调用。然后，您将验证 View 的`showAddNote()`被调用。因此，您调用一个方法并验证它反过来调用另一个方法（回想一下 MVP 模式的工作原理；presenter 与视图协调）。

目前，我们不需要担心第二个调用方法做什么；这是单元测试，您一次测试一个小东西（单元）。因此，您必须模拟出 View，并且现在不需要实现它。一些接口可以实现这一点；也就是说，一个 API 或契约而不一定要实现它们。请参阅以下代码的最终部分：

```kt
import com.packtpub.eunice.notesapp.notes.NotesContract
import com.packtpub.eunice.notesapp.notes.NotesPresenter
import org.junit.Before
import org.junit.Test
import org.mockito.Mock
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations

@Mock
private lateinit var notesView: NotesContract.View
private lateinit var notesPresenter: NotesPresenter

@Before
fun setUp() {
 MockitoAnnotations.initMocks(this)

 // The class under test
 notesPresenter = NotesPresenter()
}

@Test
fun `should display note view when button is clicked`() {
 // When adding a new note
 notesPresenter.addNewNote()

 // Then show add note UI
 verify(notesView)?.showAddNote()
}
```

现在，创建`NotesContract`，它是 MVP 架构中的**View**部分。它将是一个只需要方法以使测试通过的接口：

```kt
interface NotesContract {
    interface View {
        fun showAddNote()
    }

    interface UserActionsListener {

        fun loadNotes(forceUpdate: Boolean)

        fun addNewNote()

        fun openNoteDetails(requestedNote: Note)
    }
}
```

接下来，创建`Note`类。它代表 MVP 架构中的**Model**。它定义了您正在构建的笔记应用程序的笔记结构：

```kt
import java.util.UUID

data class Note(val title: String?,
 val description: String?,
 val imageUrl: String? = null) {

 val id: String = UUID.randomUUID().toString()
}
```

创建`NotesPresenter`，它代表 MVP 架构中的**Presenter**。让它实现`NotesContract`类中的`UserActionsListener`：

```kt
class NotesPresenter: NotesContract.UserActionsListener {
    override fun loadNotes(forceUpdate: Boolean) {
    }

    override fun addNewNote() {
    }

    override fun openNoteDetails(requestedNote: Note) {
    }
}
```

这对于第一个测试来说已经足够了。您准备好了吗？好的，现在点击测试方法所在数字旁边的右箭头。或者，您也可以右键单击`NotesPresenterTest`文件中的位置或文件并选择运行：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/39c8e93b-906f-4bab-9b3e-dde09872b839.jpg)

您的测试应该失败：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c50e97d4-36ff-422d-b102-784fb5e1562f.png)

它失败了，因为我们期望调用`NotesView`类的`showAddNote()`方法，但实际上没有。这是因为您只在`Presenter`类中实现了接口，但从未在`NotesView`类中调用预期的方法。

现在让我们继续并修复它。

首先，更新`NotesPresenter`以在其主要构造函数中接受`NotesContract.View`对象。然后，在`addNewNote()`方法中调用预期的方法`showAddNote()`。

您应该始终更喜欢构造函数注入而不是字段注入。这样更容易处理，也更容易阅读和维护。

您的`NotesPresenter`类现在应该如下所示：

```kt
class NotesPresenter(notesView: NotesContract.View): NotesContract.UserActionsListener {
    private var notesView: NotesContract.View = checkNotNull(notesView) {
        "notesView cannot be null"
    }

    override fun loadNotes(forceUpdate: Boolean) {
    }

    override fun addNewNote() = notesView.showAddNote()

    override fun openNoteDetails(requestedNote: Note) {
    }
}
```

`checkNotNull`是一个内置的`Kotlin`实用程序函数，用于验证对象是否为 null。它的第二个参数接受一个 lambda 函数，如果对象为 null，则应返回默认消息。

由于`NotesPresenter`现在在其主要构造函数中需要`NotesContract.View`，因此您必须更新测试以适应这一点：

```kt
@Before
fun setUp() {
    MockitoAnnotations.initMocks(this)

// Get a reference to the class under test
    notesPresenter = NotesPresenter(notesView)
}
```

代码已经重构。现在重新运行测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6795a76f-089d-47d4-8190-e1fe3e286a61.png)

万岁！测试现在通过了；太棒了。干得好。

这是使用**TDD**的一个完整循环。现在，您需要继续前进，在功能完全实现之前还有一些测试要完成。

您的下一个测试是验证 presenter 是否按预期显示笔记。在此过程中，您将首先从存储库中检索笔记，然后更新视图。

您将使用先前测试的类似测试 API。但是，这里有一个新的测试 API，称为`ArgumentCaptor`。正如您可能已经猜到的那样，它捕获传递给方法的参数。您将使用这些参数调用另一个方法，并将它们作为参数传递。让我们看一下：

```kt
@Mock
private lateinit var notesRepository: NotesRepository

    @Captor
    private var loadNotesCallbackCaptor: ArgumentCaptor<NotesRepository.LoadNotesCallback>? = null

private val NOTES = arrayListOf(Note("Title A", "Description A"),
 Note("Title A", "Description B"))
...

@Test
fun `should load notes from repository into view`() {
 // When loading of Notes is requested
 notesPresenter.loadNotes(true)

 // Then capture callback and invoked with stubbed notes
 verify(notesRepository)?.getNotes(loadNotesCallbackCaptor?.capture())
 loadNotesCallbackCaptor!!.value.onNotesLoaded(NOTES)

 // Then hide progress indicator and display notes
 verify(notesView).setProgressIndicator(false)
 verify(notesView).showNotes(NOTES)
}
```

让我们再简要地回顾一下。

您首先调用了要测试的方法，即`loadNotes()`。然后，您验证了该操作反过来使用`NotesRepository`实例获取笔记（`getNotes()`），就像之前的测试一样。然后，您验证了传递给`getNotes()`方法的实例，该实例再次用于加载笔记（`onNotesLoaded()`）。之后，您验证了`notesView`隐藏了进度指示器（`setProgressIndicator(false)`）并显示了笔记（`showNotes()`）。

尽可能利用 Kotlin 中的空安全功能。不要为模拟使用可空类型，而是使用 Kotlin 的`lateinit`修饰符。

这将导致代码更加清晰，因为您不必在任何地方进行空值检查，也不必使用`elvis`运算符。

现在，按照以下方式创建`NotesRepository`：

```kt
interface NotesRepository {

    interface LoadNotesCallback {

        fun onNotesLoaded(notes: List<Note>)
    }

    fun getNotes(callback: LoadNotesCallback?)
    fun refreshData()
}
```

接下来，更新`NotesContract`：

```kt
interface NotesContract {
    interface View {
        fun setProgressIndicator(active: Boolean)

        fun showNotes(notes: List<Note>)

        ...
    }

  ...
}
```

您现在已准备好测试第二个测试用例。继续并运行它：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/7408b728-8d67-4d75-9de4-e29d76a12448.png)

好的，它失败了。再次，使用 TDD，这很完美！您意识到这确切地告诉我们缺少什么，因此需要做什么。您只实现了合同（接口），但没有进一步的操作。

打开`NotesPresenter`并重构代码以使此测试通过。您将首先将`NotesRepository`添加为构造函数参数的一部分，然后在适当的方法中进行调用。请参阅以下代码以获取完整实现：

```kt
import com.packtpub.eunice.notesapp.data.NotesRepository
import com.packtpub.eunice.notesapp.util.EspressoIdlingResource

class NotesPresenter(notesView: NotesContract.View, notesRepository: NotesRepository) :
 NotesContract.UserActionsListener {

 private var notesRepository: NotesRepository = checkNotNull(notesRepository) {
 "notesRepository cannot be null"
 }

 override fun loadNotes(forceUpdate: Boolean) {
 notesView.setProgressIndicator(true)
 if (forceUpdate) {
 notesRepository.refreshData()
 }

 EspressoIdlingResource.increment()

 notesRepository.getNotes(object : NotesRepository.LoadNotesCallback {
 override fun onNotesLoaded(notes: List<Note>) {
 EspressoIdlingResource.decrement()
 notesView.setProgressIndicator(false)
 notesView.showNotes(notes)
 }
 })
 }
 ...
}
```

您使用构造函数注入将`NotesRepository`实例注入`NotesPresenter`。您检查了它的可空性，就像您对`NotesContract.View`所做的那样。

在`loadNotes()`方法中，您显示了进度指示器，并根据`forceUpdate`字段刷新了数据。

然后，您使用了一个实用类`EspressoIdlingResource`，基本上是为了提醒 Espresso 可能存在异步请求。在获取笔记时，您隐藏了进度指示器并显示了笔记。

创建一个 util 包，其中包含`EspressoIdlingResource`和`SimpleCountingIdlingResource`：

```kt
import android.support.test.espresso.IdlingResource

object EspressoIdlingResource {

    private const val RESOURCE = "GLOBAL"

    private val countingIdlingResource = SimpleCountingIdlingResource(RESOURCE)

    val idlingResource = countingIdlingResource

    fun increment() = countingIdlingResource.increment()

    fun decrement() = countingIdlingResource.decrement()
}
```

以及`SimpleCountingIdlingResource`：

```kt
package com.packtpub.eunice.notesapp.util

import android.support.test.espresso.IdlingResource
import java.util.concurrent.atomic.AtomicInteger

class SimpleCountingIdlingResource

(resourceName: String) : IdlingResource {

    private val mResourceName: String = checkNotNull(resourceName)

    private val counter = AtomicInteger(0)

    @Volatile
    private var resourceCallback: IdlingResource.ResourceCallback? =  
    null

    override fun getName() = mResourceName

    override fun isIdleNow() = counter.get() == 0

    override fun registerIdleTransitionCallback(resourceCallback: 
    IdlingResource.ResourceCallback) {
        this.resourceCallback = resourceCallback
    }

    fun increment() = counter.getAndIncrement()

    fun decrement() {
        val counterVal = counter.decrementAndGet()
        if (counterVal == 0) {
            // we've gone from non-zero to zero. That means we're idle 
            now! Tell espresso.
            resourceCallback?.onTransitionToIdle()
        }

        if (counterVal < 0) {
            throw IllegalArgumentException("Counter has been 
            corrupted!")
        }
    }
}
```

确保使用`EspressoIdlingResource`库更新应用程序的构建依赖项：

```kt
dependencies {
  ...
  implementation "com.android.support.test.espresso:espresso-idling-resource:3.0.1"
...
}
```

接下来，更新`setUp`方法以正确初始化`NotesPresenter`类：

```kt
@Before
fun setUp() {
    MockitoAnnotations.initMocks(this)

// Get a reference to the class under test
    notesPresenter = NotesPresenter(notesView)
}
```

现在一切都准备好了，运行测试：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/840cf956-4c61-45d0-bae7-ab5347e41120.png)

太棒了！真是太棒了。您已成功使用 TDD 方法编写了 NotesApp 的业务逻辑。

# Crashlytics

从官方网站：

*Firebase Crashlytics 是一个轻量级的实时崩溃报告工具，可帮助您跟踪、优先处理和修复侵蚀应用程序质量的稳定性问题。 Crashlytics 通过智能分组崩溃并突出导致崩溃的情况，节省了故障排除时间。*

就是这样，这基本上就是 Crashlytics 的全部内容。它适用于 iOS 和 Android。以下是其主要功能：

+   **崩溃报告：**其主要目的是报告崩溃，并且它确实做得很好。它可以定制以满足您的需求。例如，您可能不希望它报告某些类型的崩溃，还有其他定制选项。

+   **分析：**它提供有关崩溃的报告，包括受影响的用户、其设备、崩溃发生的时间，包括干净的堆栈跟踪和日志，以帮助调试和修复。

+   **实时警报：**您将自动收到有关新问题和重复问题的警报。实时警报是必要的，因为它们可以帮助您非常快速地解决问题。

Crashlytics 用于查找特定崩溃是否影响了大量用户。当问题突然严重性增加时，您还会收到警报，并且它允许您找出哪些代码行导致崩溃。

实施步骤如下：

+   连接

+   整合

+   检查控制台

# 连接

您将首先向您的应用程序添加 Firebase。Firebase 是一个为移动和 Web 应用程序开发的平台。它有很多工具，其中之一就是 Crashlytics。

最低要求是：

+   运行 Android 4.0（冰淇淋三明治）或更新版本的设备，并且 Google Play 服务 12.0.1 或更高版本

+   Android Studio 2.2 或更高版本

您将使用 Android Studio 2.2+中的 Firebase 助手工具将您的应用连接到 Firebase。助手工具将更新您现有的项目或创建一个带有所有必要的 Gradle 依赖项的新项目。它提供了一个非常好的直观的 UI 指南，您可以按照它进行操作：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/257940e6-ea7b-428d-996b-895332131468.jpg)

查看完整指南，了解如何将您的项目添加到 Firebase 中的第十二章，*为任务设置提醒*。完成后，从浏览器登录到 Firebase 控制台。在侧边菜单中，从**STABILITY**部分选择**Crashlytics**：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e18fef4d-54eb-4579-9d8d-7a200210c3ea.jpg)

当 Crashlytics 页面打开时，您将被问及应用程序是否是 Crashlytics 的新应用程序。选择是，这个应用程序是 Crashlytics 的新应用程序（它没有任何版本的 SDK）：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e2ebfd80-78a0-453b-bb24-981692d48a3e.png)

然后第二步会给您一个链接到文档页面，以设置您的应用的 Crashlytics。要将 Crashlytics 添加到应用中，请更新项目级别的`build.gradle`：

```kt
buildscript {
    repositories {
        // ...
        maven {
           url 'https://maven.fabric.io/public'
        }
    }
    dependencies {
        // ...
        classpath 'io.fabric.tools:gradle:1.25.1'
    }
}

allprojects {
    // ...
    repositories {
       // ...
       maven {
           url 'https://maven.google.com/'
       }
    }
}
```

然后，使用 Crashlytics 插件和依赖项更新您的应用程序模块的`build.gradle`文件：

```kt
apply plugin: 'com.android.application'
apply plugin: 'io.fabric'

dependencies {
    // ...
    implementation 'com.crashlytics.sdk.android:crashlytics:2.9.1'
}
```

就是这样，Crashlytics 已经准备好监听您的应用程序中的崩溃。这是它的默认行为，但是如果您想自己控制初始化，您将不得不在清单文件中禁用它：

```kt
<application
...
 <meta-data android:name="firebase_crashlytics_collection_enabled" android:value="false" />
</application>
```

然后，在您的 Activity 类中，您可以启用它，即使使用调试器也可以：

```kt
val fabric = Fabric.Builder(this)
        .kits(Crashlytics())
        .debuggable(true)
        .build()
Fabric.with(fabric)
```

确保您的 Gradle Wrapper 版本至少为 4.4：

```kt
distributionUrl=https\://services.gradle.org/distributions/gradle-4.4-all.zip
```

由于您的应用程序需要向控制台发送报告，请在清单文件中添加互联网权限：

```kt
<manifest ...>

  <uses-permission android:name="android.permission.INTERNET" />

  <application ...
```

像往常一样，同步 Gradle 以使用您刚刚进行的依赖项更新您的项目。

之后，您应该看到 Fabric 插件已集成到 Android Studio 中。使用您的电子邮件和密码注册：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a706d43a-a7b2-4047-8200-6465f9d94290.png)

确认您的帐户后，Fabric API 密钥将为您生成。它应该看起来像这样：

```kt
<meta-data
    android:name="io.fabric.ApiKey"
    android:value="xxYYxx6afd23n6XYf9ff6000383b4ddxxx2220faspi0x"/>
```

现在，您将强制在您的应用程序中崩溃以进行测试。创建一个新的空白活动，并只添加一个按钮。然后，将其`clicklistener`设置为强制崩溃。Crashlytics SDK 有一个简单的 API 可以做到这一点：

```kt
import kotlinx.android.synthetic.main.activity_main.*

...

override fun onCreate(savedInstanceState: Bundle?) {
 crash_btn.setOnClickListener {
  Crashlytics.getInstance().crash()
 }
}
```

由于您正在测试，崩溃后重新打开应用程序，以便报告可以发送到您的控制台。

继续运行应用程序。您的测试活动应该是这样的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4e9636e6-0f3f-430c-b472-c232cdbbdb8b.png)

点击 CRASH！按钮来强制崩溃。您的应用程序将崩溃。点击确定，然后重新打开应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/9ec06018-156b-4433-9d6a-b51f642381d5.png)

检查您的收件箱，也就是您在 Crashlytics 上注册的那个：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c07f5283-dfce-4fc5-8af9-7f00b6bbe270.png)

点击“了解更多”按钮。它将打开 Crashlytics 控制台。从那里，您可以找到有关崩溃的更多详细信息。从那里，您可以解决它。

# 测试阶段

测试有两个主要阶段：alpha 测试和 beta 测试。主要思想是在应用程序开发的阶段让一组人测试应用程序。通常是在应用程序开始成形之后，以便可以利用反馈使应用程序更加稳定。稳定性在这里是关键。区分各种测试阶段的一个关键因素是参与测试的人数。

# Alpha 测试

Alpha 测试被认为是测试软件的第一阶段。这个测试通常涉及很少数量的测试人员。在这个阶段，应用程序非常不稳定，因此只有与开发人员密切相关的少数人参与测试并提供建设性反馈。应用程序稳定后，就可以进入 beta 测试阶段。

# Beta 测试

Beta 测试是软件测试的一个阶段，其中有一个更大的人群测试应用程序。这可能涉及 10、100 或 1000 人或更多，这取决于应用程序的性质和团队的规模。如果一个应用程序在全球拥有大量用户，那么它很可能有一个庞大的团队在开发，并且因此可以承担许多人参与测试该应用程序的 beta 测试。

# 为 beta 测试设置

您可以从**Google Pay 控制台**设置和管理 beta 测试。您可以选择将您的应用程序提供给特定的 Google 组，或者您可以通过电子邮件发送邀请。

用户必须拥有 Google（@gmail.com）或 G Suite 帐户才能加入。发布后，您的链接可能需要一段时间才能对测试人员可用。

# 创建 beta 测试轨道

现在，您将需要在 Google Play 控制台内创建所谓的**轨道**。这基本上是一个用于管理测试流程的设置。

在这里，您可以上传您的 APK，将其分发给选定的一组人，并在他们测试时跟踪反馈。您还可以管理 alpha 和 beta 测试阶段。

按照以下步骤设置 beta 测试：

1.  登录到您的 Play 控制台并选择您的应用程序。

1.  在**发布管理**下找到**应用发布**，并在**Beta 轨道**下选择**管理**。

1.  在**Artifacts**部分上传您的 APK，然后展开**管理测试人员**部分。

1.  在**选择测试方法**下，选择**公开 Beta 测试**。

1.  复制**Opt-in URL**并与您的测试人员分享。

1.  在**反馈渠道**旁边提供电子邮件地址或 URL，以便从测试人员收集反馈。然后，点击**保存**来保存它。

# Opt-in URL

创建测试后，发布它。然后，您将获得测试链接。其格式如下：[`play.google.com/apps/testing/com.yourpackage.name`](https://play.google.com/apps/testing/com.yourpackage.name.)。现在，您必须与您的测试人员分享此链接。有了这个链接，他们可以选择测试您的应用程序。

# 持续集成

通常，一个应用可能有多个人（团队）在进行工作。例如，A 可能负责 UI，B 负责功能 1，C 负责业务逻辑中的功能 2。这样的项目仍然会有一个代码库以及其测试和其他一切。所有提交者可能会在推送代码之前在本地运行测试以确保自己的工作正常。具有不同提交者的共享存储库中的代码必须统一并构建为一个完整的应用程序（集成）。还必须对整个应用程序运行测试。这必须定期进行，在 CI 的情况下，每次提交都要进行。因此，在一天内，共享存储库中的代码将被构建和测试多次。这就是持续集成的概念。以下是一个非常简单的图表，显示了 CI 过程的流程。它从左边（开发）开始：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/cdf09475-ece3-4615-9315-760d518fcfea.png)

# 定义

CI 是一种软件开发实践，其中设置了一个自动化系统，用于在代码检入版本控制后构建、测试和报告软件的情况。**集成**发生是因为各种分支合并到主分支中。这意味着主分支中的任何内容都有效地代表了整个应用程序的当前状态，而且由于这每次代码进入主存储库时都会发生，所以它是**持续的**；因此，**持续集成**。

在 CI 中，每当提交代码时，自动构建系统会自动从共享存储库（主分支）中获取最新代码并构建、测试和验证整个分支。通过定期执行此操作，可以快速检测到错误，从而可以快速修复。知道您的提交可能会导致不稳定的构建，因此只能提交小的更改。这也使得易于识别和修复错误。

这非常重要，因为尽管应用程序的不同部分经过了单独测试和构建，但在它们合并到共享存储库后可能并不是必要的。然后，每次检入都会由自动构建进行验证，允许团队及早发现问题。

同样，还有持续部署以及持续交付。

# 工具

有许多可用于 CI 的工具。有些是开源的，有些是自托管的，有些更适合于 Web 前端，有些更适合于 Web 后端，有些更适合于移动开发。

示例包括 Jenkins、Bamboo 和 Fastlane。您将使用 Fastlane 来集成您的应用程序并运行测试。Fastlane 是自托管的，这意味着您在开发机器上运行它。理想情况下，您应该将其安装在 CI 服务器上，即专用于 CI 任务的服务器。

首先，让我们在本地安装它，并使用它来运行 Notes 应用程序的测试。

在撰写本书时，Fastlane 仅在 MacOS 上运行。目前正在进行工作，以使其在 Linux 和 Windows 上运行。一些 CI 服务包括 Jenkins、Bamboo、GitLab CI、Circle CI 和 Travis。

# 安装 fastlane

要安装 fastlane，请按照以下步骤进行操作：

1.  您应该已经在终端中的路径上有**`gem`**，因为 x-code 使用 Ruby 并且捆绑在 Mac OS X 中。运行以下命令进行安装：

```kt
brew cask install fastlane
```

根据您的用户帐户权限，您可能需要使用`sudo`。

1.  成功安装后，将`bin`目录的路径导出到您的`PATH`环境变量中：

```kt
export PATH="$HOME/.fastlane/bin:$PATH"
```

1.  在此期间，还添加以下区域设置：

```kt
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
```

1.  在终端中打开一个新会话。这个新会话将加载您刚刚对环境变量所做的更改。首先，确保您已安装`bundler`。如果尚未安装，请使用以下命令：

```kt
[sudo] gem install bundler
```

1.  然后，切换到您的工作目录的根目录。然后，使用以下命令初始化`fastlane`：

```kt
fastlane init
```

作为过程的一部分，您将被问及一些问题。首先是您的包名称。当您留空时，将提供默认值，因此请输入您的包名称：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d4101973-7c49-4029-a07a-891247a1ac5b.png)

1.  接下来，您将被要求提供某个服务操作 JSON 秘密文件的路径。只需按*Enter*，因为我们暂时不需要它；稍后可以提供。最后，您将被问及是否要上传一些元数据等内容。请谦逊地拒绝；您可以稍后使用以下命令进行设置：

```kt
fastlane supply init
```

还会有一些其他提示，您只需按*Enter*键即可。

1.  完成后，使用以下命令运行您的测试：

```kt
fastlane test
```

一切顺利时，您应该会看到以下结果：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6fe3d173-e43b-471f-b080-44b955de79ad.png)

# 总结

在本章中，您已经了解了 CI 和测试的概念。您已经学会了如何使用 ATSL 编写测试。

您了解了测试中最流行的两个阶段以及如何在 Google Play 控制台中设置它们。您尝试了 Crashlytics，并体验了其崩溃报告功能等。然后您了解了 CI，并且作为示例，您使用了名为 Fastlane 的 CI 工具之一。

哇，这一章真的很充实，您已经到达了结尾。在下一章中，您将学习如何“让您的应用程序面向全球”。有趣，对吧？好吧，让我们继续吧；我们下一章再见。


# 第十四章：使您的应用程序面向全球

在经过多个小时的工作和学习许多新知识后构建应用程序，开发人员的最终满足感是看到用户轻松下载并享受使用应用程序的体验，从中获得最大的使用价值。

在本章中，我们将学习通过 Google Play 商店和亚马逊应用商店分发我们的应用程序所涉及的各种步骤。我们还将了解数字签名我们的应用程序以验证其真实性。

在本章中，重点将是学习以下内容：

+   通过 Android Studio 和命令行生成密钥库

+   通过 Google Play 商店发布应用程序

+   通过亚马逊应用商店发布应用程序

# 密钥库生成

Android 的最重要的安全功能之一是允许安装 APK，但只能来自受信任的来源，如 Google Play 商店或亚马逊应用商店。这些分发渠道要求开发人员对应用程序进行身份验证，声明这确实是他或她打算分发的应用程序。

应用程序的所有者，即开发人员，将拥有私钥，并且分发渠道将使用相应的公钥对其进行签名。公钥和私钥的组合意味着数字签名存储在`keyStore`文件中。`keyStore`是一个二进制文件，其中存储了用于对应用程序进行签名的数字密钥。

在将应用程序发布到 Google Play 商店进行分发之前，必须对 APK 进行数字签名。数字签名用作开发人员的身份验证，并确保只能通过受信任的来源进行应用程序更新。

保持密钥库文件的安全并记住密钥密码非常重要。一旦使用密钥库文件对应用程序进行签名并发布，任何对应用程序的进一步更新只能使用相同的密钥进行。

`KeyStore`可以通过几种方式生成：

+   Android Studio

+   命令行

让我们详细讨论生成密钥库所涉及的步骤。

# 通过 Android Studio 生成密钥库

这些是我们需要遵循的通过 Android 生成密钥库的步骤：

1.  一旦打开我们希望为其生成 APK 的项目，点击“构建|生成已签名 APK**。**”这将导致“生成已签名 APK”屏幕显示。 Android Studio 期望用户选择密钥库路径：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c9ac4376-b811-4ff7-b38a-8e030ce63796.png)

1.  由于我们将生成一个新的密钥库，点击“创建新”按钮。这将显示如下的“新密钥库”窗口：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/444a4f85-f43a-40e8-bf21-79fc39dd9bb1.png)

1.  选择密钥库路径并为`.jks`（Java 密钥库）文件提供名称：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/94d5b9d4-a6fc-4004-ad46-b3ef943e9d9f.png)

1.  确认密钥库路径后，我们需要填写密钥库密码、密钥别名、密钥别名密码、名字和姓氏、组织单位、组织、城市或地点、州或省和国家代码（XX）：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/25ecf02c-068d-417a-8988-b7b01c897be8.png)

1.  一旦填写了所需的详细信息并点击“确定”按钮，我们应该能够继续进行“生成已签名 APK”屏幕。点击下一步：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/f0f56374-a0ec-4471-8c32-e69c610ef506.png)

1.  在下一个屏幕上，我们将有选择 APK 目标文件夹和构建类型的选项。然后，点击“完成”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/f71ee512-86de-4821-adce-fd03db5b1d6f.png)

1.  完成后，控制台中显示已签名 APK 的生成确认以及定位或分析 APK 的选项：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/20790051-e811-489b-bcd6-38fe45b1f15c.png)

1.  已签名 APK 经过数字签名，可以通过 Google Play 商店和其他发布平台发布，并且可以在目标文件夹中找到：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/5be464c0-d783-4cc2-bb4c-444d79bc07c1.png)

1.  现在我们已经生成了密钥库，以后每当我们更新应用程序时，Android Studio 都会提供我们生成已签名 APK 的屏幕，并期望填写密码：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2919050f-4ea7-4de4-acf3-2c4c6efe53be.png)

按照新*密钥库* *生成*中描述的相同过程，用户应该能够生成已签名的 APK。

# 通过 Android Studio 自动签署 APK

我们有选项，可以在对应用程序进行更改时自动生成已签名的 APK。这可以通过在 Android Studio 中执行以下操作来实现：

1.  右键单击**App** | **项目结构**。

1.  选择签名标签。在此标签中，我们需要提供应用程序签名配置的详细信息。在这里，我们将其命名为`config`，并存储密钥别名、密码和存储文件的路径：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6705b337-6114-47cb-8b5a-ea447d13b43f.png)

添加签名`config`将导致签名详细信息以纯文本形式添加到`build.gradle`文件中：

```kt
android {
     signingConfigs {
         config {
             keyAlias 'packtkey' keyPassword 'vasantham' storeFile file('G:/newkey/dreamindia.jks')
             storePassword 'vasantham' } 

```

将此信息移出构建文件以确保敏感信息不易被他人访问是明智的。在项目的根目录中，我们应该创建一个名为`keystore.properties`的文件。该文件将包含以下信息：

```kt
storePassword = OurStorePassword
KeyPassword = ourKeyPassword
keyAlias = ourKeyAlias
storeFile = ourStoreFileLocation
```

由于我们已经将密钥库详细信息移动到单独的文件中，现在我们应该在`build.gradle`文件中添加以下代码，以确保签名配置可用于自动签署 APK。我们应该在`android{}`块之前加载`keystore.properties`文件。

在此代码中，我们创建了一个名为`keystorePropertiesFile`的变量，并将其初始化为我们创建的`keystore.properties`文件。此外，我们初始化了一个名为`keyStoreProperties`的新`Properties()`对象。`keystorePropertiesFile`的详细信息被加载到`keystoreProperties`对象中：

```kt
def keystorePropertiesFile = rootProject.file("keystore.properties")
def keystoreProperties = new Properties()
keystoreProperties.load(new FileInputStream(keystorePropertiesFile))

android {
.......
}
```

通过添加上述代码，我们可以使用`keystoreProperties['propertyName']`的语法引用存储在`keystoreProperties`中的所有属性***。***我们应该能够修改`build.gradle`文件中的签名配置，如下面的代码所示：

```kt
android {
     signingConfigs {
         config {
             keyAlias keystoreProperties['keyAlias'] keyPassword keystoreProperties['keyPassword'] storeFile file(keystoreProperties['storeFile'])
             storePassword keystoreProperties['storePassword'] } 
}
..........
}
```

构建文件现在是安全的，不包含任何敏感信息。如果我们要使用任何源代码控制或共享代码库，我们需要确保删除并保护`keystore.properties`文件。

# 构建类型和风味

开发人员可以通过`build.gradle`文件维护构建类型中的变体，并且可以通过配置来配置这些变体。该配置使开发人员能够在同一应用程序中维护调试代码和发布版本的代码：

+   **调试：**打开调试选项**并且**也可以使用调试密钥签署应用程序

+   **发布：**关闭调试选项，使用发布密钥签署应用程序，并且还会减少或删除最终 APK 中与调试相关的代码

我们可以在 Android Studio 中定义调试或发布类型的构建：

1.  右键单击 app | 项目结构。

1.  在构建类型标签中，我们需要添加一个新的构建变体类型。我们有两种构建类型，调试和发布，如下截图所示。在创建构建类型时，我们将有选项选择构建变体的签名配置：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/8bfdaa86-84ef-475d-98c3-f8a730347f15.png)

这将在`build.gradle`文件中添加以下代码：

```kt
    buildTypes {
         release {
             minifyEnabled false proguardFiles getDefaultProguardFile('proguard-
             android.txt'), 'proguard-rules.pro' signingConfig signingConfigs.config }
     }
```

在应用程序世界中，为免费应用程序提供基本功能，并为付费应用程序提供高级功能是一种通用规范。Android 提供了将它们定义为**productFlavors**的选项。

免费和付费是开发人员常用的产品风味。通过定义各种产品风味，开发人员将有选择地维护不同的代码，从而为同一应用程序提供不同或额外的功能。免费和付费版本提供的共同功能的代码基础可以相同，而付费产品风味版本可以启用高级功能。

要定义产品口味，右键单击**app** |** Project Structure**，在 Flavors 选项卡中，可以定义产品口味-免费或付费。签名配置也可以自定义以匹配`productFlavors`：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/0a356a2e-9508-438b-bdd1-c5fc96c1f43f.png)

`build.gradle`文件将包含以下信息：

```kt
android {
........
     productFlavors {
         paid {
             signingConfig signingConfigs.paidconfig }
         free {
             signingConfig signingConfigs.freeconfig }
     }
 }
```

# 通过命令行生成密钥库

密钥库也可以通过使用 keytool 命令行生成。keytool 可在 jdk 的`bin`目录中找到：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/22b2c77a-f1e9-4695-aba5-e564962563cc.png)

启动命令提示符并运行以下命令：

```kt
keytool -genkey -v -keystore dreamindiacmd.jks -keyalg RSA -keysize 2048 -validity 10000 -alias packtcmdkey
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/f0f113f4-e4de-4e86-9980-416174331acc.png)

上述命令需要一个密钥库路径，用于密钥签名的安全算法类型，密钥大小，有效期和密钥别名。执行上述命令后，我们需要提供密码和一些其他额外的细节，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/caa30500-3927-480a-a911-2c3a334bd3ea.png)

成功执行命令后，我们可以在 keytool 的相同位置找到生成的`keystore`文件：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/983beac9-97b7-469e-9d31-697c2feee2ca.png)

# 在 Google Play 商店发布应用

现在我们有签名发布版本的 APK 可用，是时候通过 Google Play 商店进行全球分发了。

注册 Google Play 商店开发者帐户需要一次性费用 25 美元。登录[`play.google.com/apps/publish/`](https://play.google.com/apps/publish/)并完成注册过程。

Google Play 商店提供了一个名为 Google Play 控制台的优秀控制台，该控制台包含了管理 Android 应用程序发布生命周期所需的所有功能。我们将看一下使我们能够发布应用的重要功能。

发布应用的第一步是在 Google Play 控制台中创建应用程序。控制台提供了创建应用程序的选项，从而启动了发布流程：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d9df6089-18c7-475c-9afa-0ca69b0589f1.png)

一旦我们点击“创建应用程序”，就会提示我们输入默认语言和应用程序的标题。点击创建按钮将为我们创建应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/8a255bae-7921-4d7c-b96d-5212483e4c62.png)

开发者控制台提供了许多选项供开发者在菜单中填写。但是，有四个重要且必填的部分需要填写，以确保应用程序可以发布。

这四个部分分别是应用发布、商店列表、内容评级和定价与分发：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/04b29151-2e78-4a46-a1a4-7050d5c96498.png)

现在，让我们专注于这些必填部分需要填写的细节。

# 应用发布部分

应用发布部分使开发者能够管理 APK 发布的整个生命周期。开发者可以在将 APK 移至公共分发之前，将其应用于内部测试、alpha 和 beta 发布。发布的各个阶段帮助开发者收集有关应用的反馈，通过限制应用，使其仅对特定用户可用：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4a8a61a8-455c-47e5-ad6e-e8e5dc016d4c.png)

我们需要上传为构建类型发布生成的签名 APK，以便进行生产。可以浏览 APK 文件并将其上传到 Play 商店：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/8cae8811-de6a-4876-a4df-137356ab8e34.png)

一旦 APK 上传完成，可以在发布部分找到相同的版本代码和删除 APK 的选项。上传签名的 APK 完成了应用发布部分所需的详细信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/096fdd4c-2235-4c42-bf7c-5b8aa11d4e8c.png)

# 商店列表部分

商店列表部分是接下来要关注的部分。这是一个重要的部分，因为用户将在这里看到应用的各种截图、简短和详细描述。开发人员可以选择保存草稿，并随时返回继续填写详细信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/359584c3-af8d-4675-99f4-da36313b2a10.png)

在 Google Play 商店中，商店列表部分要求以下内容：

+   应用的两个截图

+   高分辨率图标 - 512 * 512

+   特色图形 - 1,024 W x 500 H：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d35945b8-42d4-483e-b49a-d7aa64bc8316.png)

可以使用免费的图像编辑器（如**gimp**）创建图形资产。遵循图形规范的指南非常重要且强制性。

开发人员需要提供应用程序的类型和类别以及联系方式和隐私政策（如果有的话）。一旦提供了所有详细信息，商店列表部分将完成。

# 内容评级部分

开发人员应该对应用中提供的内容进行自我声明。内容评级部分有一个问卷，要求开发人员提供具体答案。回答问卷是一项简单的任务：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d7babce2-d3f2-4444-9191-da12983dff6f.png)

开发人员提供有关应用内容的正确信息非常重要，因为提供错误信息可能会影响商店列表。

# 定价和分发部分

最后一个强制性部分，定价和分发，要求开发人员提供与其应用定价相关的信息 - 免费或付费，应用分发的国家列表，应用是否主要面向儿童，应用是否包含广告，内容指南，以及开发人员承诺遵守美国出口法的确认：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4ead3aba-fa15-4fba-9cdb-b87d0004667b.png)

一旦开发人员在定价和分发部分提供了所有必要的详细信息，将出现“准备发布”的消息。还要注意，所有四个强制性部分都标记为绿色，表示已完成：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2351c62b-d7cd-441b-b1e7-63d2dad21fed.png)

一旦应用提交发布，将在几小时内进行审核并提供下载。如果有任何疑问，开发人员需要解决并重新提交应用以发布。

# 在亚马逊应用商店发布应用

亚马逊应用商店为开发人员提供了一个免费的市场来分发他们的 Android 应用。开发人员可以登录并在以下网址创建他们的免费账户：[`developer.amazon.com/apps-and-games/app-submission/android.`](https://developer.amazon.com/apps-and-games/app-submission/android)

一旦我们登录应用商店，我们需要点击亚马逊应用商店中的“添加 Android 应用”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c12f4793-9c16-4dec-ae88-9d976ab7483a.png)

亚马逊应用商店要求填写以下部分：常规信息、可用性和定价、描述、图像和多媒体、内容评级和二进制文件。

让我们详细看看这些部分。

# 常规信息

在常规信息部分，开发人员需要提供有关应用标题、包名称、应用 ID、发布 ID、应用类别以及开发人员的联系方式的信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c446bd6e-a3cb-4e76-9c7d-a80e60a2fe75.png)

# 可用性和定价部分

在这一部分，开发人员需要提供以下信息：

+   应用的定价 - 免费或付费

+   国家列表

+   应用发布的日期和时间：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/3cadd242-28fb-4f5f-bdaf-dfd0394e1707.png)

# 描述部分

在描述部分，开发人员需要填写有关标题、简短描述和长描述的详细信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/11555c56-54bf-4cad-84b2-ceaac768536e.png)

该部分还使开发人员能够提供产品特色项目和识别应用的特定关键字。用户还可以选择添加本地化描述：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/3f73a9a7-764c-4fb2-ad00-6dc976fe6ec6.png)

# 图像和多媒体部分

在图像和多媒体部分，开发人员需要输入与应用相关的图形资产。用户需要提供： 

+   **图标**：512 * 512 PNG 和 114 * 114 PNG

+   **屏幕截图**：3 到 10 个 PNG 或 JPG

还有一个选项可以提供与平板电脑和手机等形态因素相关的图形：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/f5f4f1c9-ae66-4fdd-a738-d1527f517065.png)

# 内容评级部分

在内容评级部分，开发人员需要回答一系列与应用中显示的内容性质相关的问题。这些问题属于主题：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/0cd6474e-a7d1-4452-a00b-8751e678ba4f.png)

开发人员需要回答关于使用基于位置的服务、应用中的广告、提供隐私政策（如果有的话）以及披露应用是否面向 13 岁以下儿童的问题：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/ecc4aa67-40d5-4c04-90bd-f3fe1b02f53e.png)

# 二进制文件部分

在此部分，开发人员应上传从 Android Studio 或命令行生成的已签名 APK：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/39094e6c-ad97-4a9e-8066-7ebae7a6288c.png)

开发人员还可以决定设备支持、语言支持、出口合规性和使用亚马逊地图重定向的选项：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/16c9800e-def0-4976-8a77-640b27a3725e.png)

非亚马逊 Android 设备的设备支持默认情况下是未启用的。开发人员需要通过单击“编辑设备支持”并进行所需更改来显式启用此功能。

填写完所有必需信息后，现在是时候在亚马逊应用商店中实际发布应用了。开发人员将有一个选项来审查他们输入的所有信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c9258231-4b5a-419d-98a8-164c1bebf487.png)

# 摘要

商店列表、关键字、描述等在应用识别和最终应用及开发人员的成功方面起着重要作用。

在本章中，我们讨论了使用 Android Studio 生成密钥库文件、自动签名 APK、从命令行生成密钥库文件以及通过 Google Play 商店和亚马逊应用商店发布应用所涉及的各种步骤。

在下一章中，我们将学习如何使用我们可以使用的最有趣和重要的 API 之一——Google Faces API。Google Faces API 使开发人员能够提供诸如面部检测、照片中人物的识别等酷功能。


# 第十五章：使用 Google Faces API 构建应用程序

计算机执行识别对象等任务的能力一直是软件和所需架构的巨大任务。自从谷歌、亚马逊和其他一些公司已经完成了所有艰苦的工作，提供了基础架构，并将其作为云服务提供，这种情况已经不再存在。应该注意的是，它们可以像进行 REST API 调用一样容易访问。

在本章中，您将学习如何使用谷歌移动视觉 API 的人脸检测 API 来检测人脸，并添加有趣的功能，比如给用户的图片添加兔子耳朵。

在本章中，将涵盖以下主题：

+   在图像中识别人脸

+   从摄像头源跟踪人脸

+   识别面部的特定部位（例如眼睛、耳朵、鼻子和嘴巴）

+   在图像中的特定部位上绘制图形（例如，在用户的耳朵上添加兔子耳朵）

# 移动视觉简介

移动视觉 API 提供了一个框架，用于在照片和视频中查找对象。该框架可以定位和描述图像或视频帧中的视觉对象，并具有一个事件驱动的 API，跟踪这些对象的位置。

目前，Mobile Vision API 包括**人脸**、**条形码**和**文本**检测器。

# 人脸 API 概念

在深入编码功能之前，有必要了解人脸检测 API 的基本概念。

来自官方文档：

<q>人脸检测是自动在视觉媒体（数字图像或视频）中定位人脸的过程。检测到的人脸将以位置、大小和方向进行报告。一旦检测到人脸，就可以搜索眼睛和鼻子等地标。</q>

需要注意的一个关键点是，只有在检测到人脸后，才会搜索眼睛和鼻子等地标。作为 API 的一部分，您可以选择不检测这些地标。

请注意人脸检测和人脸识别之间的区别。前者能够从图像或视频中识别人脸，而后者则可以做到同样，并且还能够告诉人脸之前是否已经被识别过。前者对其之前检测到的人脸没有记忆。

在本节中，我们将使用一些术语，所以在我们进一步之前，让我给您概述一下每个术语：

**人脸跟踪**将人脸检测扩展到视频序列。当视频中出现人脸时，可以将其识别为同一个人并进行跟踪。

需要注意的是，您正在跟踪的人脸必须出现在同一个视频中。此外，这不是一种人脸识别形式；这种机制只是根据视频序列中面部的位置和运动进行推断。

**地标**是面部内的一个感兴趣的点。左眼、右眼和鼻子底部都是地标的例子。人脸 API 提供了在检测到的人脸上找到地标的能力。

**分类**是确定某种面部特征是否存在。例如，可以根据面部是否睁着眼睛、闭着眼睛或微笑来对面部进行分类。

# 入门-检测人脸

您将首先学习如何在照片中检测人脸及其相关的地标。

为了追求这一目标，我们需要一些要求。

在 Google Play 服务 7.8 及以上版本中，您可以使用 Mobile Vision API 提供的人脸检测 API。请确保您从 SDK 管理器中更新您的 Google Play 服务，以满足此要求。

获取运行 Android 4.2.2 或更高版本的 Android 设备或配置好的 Android 模拟器。最新版本的 Android SDK 包括 SDK 工具组件。

# 创建 FunyFace 项目

创建一个名为 FunyFace 的新项目。打开应用程序模块的`build.gradle`文件，并更新依赖项以包括 Mobile Vision API：

```kt
dependencies {
    implementation fileTree(dir: 'libs', include: ['*.jar'])
    implementation"org.jetbrains.kotlin:kotlin-stdlib-jre7:$kotlin_version"
    implementation 'com.google.android.gms:play-services-vision:11.0.4'
    ...
}
```

好了，让我们开始吧——这就是你将看到所有这些如何发挥作用的地方。

```kt
<meta-data
 android:name="com.google.android.gms.vision.DEPENDENCIES"
 android:value="face" />
```

在你的`detectFace()`方法中，你将首先从 drawable 文件夹中将图像加载到内存中，并从中创建一个位图图像。由于当检测到面部时，你将更新这个位图来绘制在上面，所以你需要将它设置为可变的。这就是使你的位图可变的方法。

为了简化操作，对于这个实验，你只需要处理应用程序中已经存在的图像。将以下图像添加到你的`res/drawable`文件夹中。

现在，这就是你将如何进行面部检测的方法。

现在，更新你的`AndroidManifest.xml`，包括面部 API 的元数据。

首先将图像加载到内存中，获取一个`Paint`实例，并基于原始图像创建一个临时位图，然后创建一个画布。使用位图创建一个帧，然后在`FaceDetector`上调用 detect 方法，使用这个帧来获取面部对象的`SparseArray`。

创建一个 Paint 实例。

查看以下代码：

```kt
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    tools:context="com.packtpub.eunice.funyface.MainActivity">

  <ImageView
      android:id="@+id/imageView"
      android:layout_width="match_parent"
      android:layout_height="match_parent"
      android:src="img/ic_launcher_round"
      app:layout_constraintBottom_toTopOf="parent"
      android:scaleType="fitCenter"/>

  <Button
      android:id="@+id/button"
      android:layout_width="wrap_content"
      android:layout_height="wrap_content"
      android:layout_gravity="bottom|center"
      android:text="Detect Face"/>

</FrameLayout>

```

这就是你在这里需要做的一切，这样你就有了一个带有`ImageView`和一个按钮的`FrameLayout`。现在，打开`MainActivity.kt`并添加以下导入语句。这只是为了确保你在移动过程中从正确的包中导入。在你的`onCreate()`方法中，将点击监听器附加到`MainActivity`布局文件中的按钮。

```kt
package com.packtpub.eunice.funface

import android.graphics.*
import android.graphics.drawable.BitmapDrawable
import android.os.Bundle
import android.support.v7.app.AlertDialog
import android.support.v7.app.AppCompatActivity
import com.google.android.gms.vision.Frame
import com.google.android.gms.vision.face.FaceDetector
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        button.setOnClickListener {
            detectFace()
        }
    }
}
```

# 加载图像。

使用`Paint` API 获取`Paint`类的实例。你只会在面部周围绘制，而不是整个面部。为此，设置一个细线，给它一个颜色，在我们的例子中是红色，并将绘画样式设置为`STROKE`。

```kt
options.inMutable=true
```

查看以下实现：

```kt
private fun detectFace() {
    // Load the image
    val bitmapOptions = BitmapFactory.Options()
    bitmapOptions.inMutable = true
    val myBitmap = BitmapFactory.decodeResource(
            applicationContext.resources,
            R.drawable.children_group_picture,
            bitmapOptions)
}
```

# 现在，你的应用程序已经准备好使用面部检测 API。

现在，你将使用`faceDetector`实例的`detect()`方法来获取面部及其元数据。结果将是`SparseArray`的`Face`对象。

```kt
// Get a Paint instance
val myRectPaint = Paint()
myRectPaint.strokeWidth = 5F
myRectPaint.color = Color.RED
myRectPaint.style = Paint.Style.STROKE 

```

`Paint`类保存与文本、位图和各种形状相关的*样式*和*颜色*的信息。

# 创建一个画布。

要获得画布，首先使用之前创建的位图的尺寸创建一个位图。有了这个画布，你将在位图上绘制面部的轮廓。

```kt
// Create a canvas using the dimensions from the image's bitmap
val tempBitmap = Bitmap.createBitmap(myBitmap.width, myBitmap.height, Bitmap.Config.RGB_565)
val tempCanvas = Canvas(tempBitmap)
tempCanvas.drawBitmap(myBitmap, 0F, 0F, null)
```

`Canvas`类用于保存绘制的调用。画布是一个绘图表面，它提供了各种方法来绘制到位图上。

# 创建面部检测器。

到目前为止，你所做的基本上是一些前期工作。现在你将通过 FaceDetector API 访问面部检测，你将在这个阶段禁用跟踪，因为你只想检测图像中的面部。

请注意，在第一次运行时，Play 服务 SDK 将需要一些时间来初始化 Faces API。在你打算使用它的时候，它可能已经完成了这个过程，也可能没有。因此，作为一个安全检查，你需要确保在使用它之前它是可用的。在这种情况下，如果`FaceDetector`在应用程序运行时还没有准备好，你将向用户显示一个简单的对话框。

还要注意，由于 SDK 的初始化，你可能需要互联网连接。你还需要确保有足够的空间，因为初始化可能会下载一些本地库到设备上。

```kt
// Create a FaceDetector
val faceDetector = FaceDetector.Builder(applicationContext).setTrackingEnabled(false)
        .build()
if (!faceDetector.isOperational) {
    AlertDialog.Builder(this)
            .setMessage("Could not set up the face detector!")
            .show()
    return
}
```

# 检测面部。

首先，打开你的`activity_main.xml`文件，并更新布局，使其包含一个图像视图和一个按钮。

```kt
// Detect the faces
val frame = Frame.Builder().setBitmap(myBitmap).build()
val faces = faceDetector.detect(frame)
```

# 在面部上绘制矩形。

现在你有了面部，你将遍历这个数组，以获取面部边界矩形的坐标。矩形需要左上角和右下角的`x`，`y`，但可用的信息只给出了左上角的位置，所以你需要使用左上角、宽度和高度来计算右下角。然后，你需要释放`faceDetector`以释放资源。

```kt
// Mark out the identified face
for (i in 0 until faces.size()) {
    val thisFace = faces.valueAt(i)
    val left = thisFace.position.x
    val top = thisFace.position.y
    val right = left + thisFace.width
    val bottom = top + thisFace.height
    tempCanvas.drawRoundRect(RectF(left, top, right, bottom), 2F, 2F, myRectPaint)
}

imageView.setImageDrawable(BitmapDrawable(resources, tempBitmap))

// Release the FaceDetector
faceDetector.release()
```

# 结果。

一切准备就绪。运行应用程序，点击“检测面部”按钮，然后等一会儿...

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/784e912e-461c-42b5-b1d6-a0ac18c096e2.png)

该应用程序应该能够检测到人脸，并在人脸周围出现一个方框，完成：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/71235c88-1ca6-4ac3-b85b-9c3b4488cb53.png)

好的，让我们继续为他们的脸部添加一些乐趣。要做到这一点，您需要确定您想要的特定地标的位置，然后在其上绘制。

要找出地标的表示，这次您要对它们进行标记，然后在所需位置绘制您的滤镜。

要进行标记，请更新绘制人脸周围矩形的 for 循环：

```kt
// Mark out the identified face
for (i in 0 until faces.size()) {
    ...

    for (landmark in thisFace.landmarks) {
        val x = landmark.position.x
        val y = landmark.position.y

        when (landmark.type) {
            NOSE_BASE -> {
                val scaledWidth = 
                       eyePatchBitmap.getScaledWidth(tempCanvas)
                val scaledHeight = 
                       eyePatchBitmap.getScaledHeight(tempCanvas)
                tempCanvas.drawBitmap(eyePatchBitmap,
                        x - scaledWidth / 2,
                        y - scaledHeight / 2,
                        null)
            }
        }
    }
}
```

运行应用程序并注意各个地标的标签：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b183ac20-c006-4bcb-9066-28510bfaed67.png)

就是这样！很有趣，对吧？

# 摘要

在本章中，您学习了如何使用移动视觉 API，这里使用的是 Faces API。这里有几件事情需要注意。该程序并非针对生产进行优化。您可以自行加载图像并在后台线程中进行处理。您还可以提供功能，允许用户从除静态源之外的不同来源选择图像。您还可以更有创意地使用滤镜以及它们的应用方式。此外，您还可以在 FaceDetector 实例上启用跟踪功能，并输入视频以尝试人脸跟踪。


# 第十六章：您可能会喜欢的其他书籍

如果您喜欢这本书，您可能会对 Packt 的其他书感兴趣：

![](https://www.packtpub.com/web-development/microservices-kotlin)

**使用 Kotlin 实践微服务**

Juan Antonio Medina Iglesias

ISBN：9781788471459

+   了解微服务架构和原则

+   使用 Spring Boot 2.0 和 Spring Framework 5.0 在 Kotlin 中构建微服务

+   使用 Spring WebFlux 创建执行非阻塞操作的响应式微服务

+   使用 Spring Data 从 MongoDB 响应式获取数据

+   使用 JUnit 和 Kotlin 进行有效测试

+   使用 Spring Cloud 创建云原生微服务

+   构建和发布微服务的 Docker 镜像

+   使用 Docker Swarm 扩展微服务

+   使用 JMX 监控微服务

+   在 OpenShift Online 中部署微服务

![](https://www.packtpub.com/application-development/building-applications-spring-5-and-kotlin)

**使用 Spring 5 和 Kotlin 构建应用程序**

Miloš Vasić

ISBN：9781788394802

+   使用 Kotlin 探索 Spring 5 的概念

+   学习依赖注入和复杂配置

+   在您的应用程序中利用 Spring Data，Spring Cloud 和 Spring Security

+   使用 Project Reactor 创建高效的响应式系统

+   为您的 Spring/Kotlin 应用编写单元测试

+   在 AWS 等云平台上部署应用程序

# 留下评论-让其他读者知道您的想法

请在购买书籍的网站上留下您对本书的想法。如果您从亚马逊购买了这本书，请在该书的亚马逊页面上留下诚实的评论。这对其他潜在读者来说非常重要，他们可以看到并使用您的公正意见来做出购买决策，我们可以了解我们的客户对我们的产品的看法，我们的作者可以看到您与 Packt 合作创建的标题的反馈。这只需要您几分钟的时间，但对其他潜在客户，我们的作者和 Packt 都是有价值的。谢谢！
