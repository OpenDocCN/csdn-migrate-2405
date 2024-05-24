# Eclipse ADT 教程（四）

> 原文：[`zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363`](https://zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：观察模式

在上一章，我们探讨了如何通过允许用户存储经常使用的数据，如位置和饮食偏好，来简化交互。这只是让应用使用尽可能愉快的一种方式。另一种有价值的方法是向用户提供及时的通知。

![观察模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_001.jpg)

所有移动设备都有接收通知的机制；通常这些通知是通过屏幕顶部的狭窄状态栏传递的，Android 也不例外。对于我们开发者来说，这个过程之所以有趣，是因为这些通知需要在我们的应用可能并未使用时发送。显然，在活动中没有回调方法来处理此类事件，因此我们将不得不查看如**服务**这样的后台组件来触发此类事件。

就设计模式而言，有一个几乎专为管理一对多关系而设计的模式，即**观察者模式**。尽管它完美适用于通知的发送和接收，但观察者模式在软件设计的各个领域无处不在，你无疑已经遇到了**Observer**和**Observed**的 Java 实用工具。

我们将从观察者模式本身以及 Android 通知的设计、构建和自定义方法开始本章的学习。

在本章中，你将学习如何：

+   创建一个观察者模式

+   发出通知

+   使用 Java 观察者工具

+   应用一个待定意图

+   配置隐私和优先级设置

+   自定义通知

+   创建一个服务

本章主要关注观察者模式，以及如何将其应用于管理通知。最好的起点是查看模式本身，它的目的和结构。

# 观察者模式

你可能没有意识到，其实你已经多次遇到观察者模式，因为每个点击监听器（以及其他任何监听器）实际上都是一个观察者。同样，对于任何桌面或图形用户界面的图标和功能，这些类型的监听器接口非常清晰地展示了观察者模式的目的。

+   观察者像一个哨兵，监视其主体（或主体）的特定事件或状态变化，然后将这些信息报告给感兴趣的相关方。

如已经提到，Java 有自己的观察者工具，尽管在某些情况下它们可能很有用，但 Java 处理继承的方式和模式的简单性使得编写我们自己的版本更为可取。我们将了解如何使用这些内置类，但在大多数示例中，我们将构建自己的版本。这还将提供对模式工作原理的更深入理解。

使用通知时必须谨慎，因为没有什么比不希望收到的消息更能激怒用户了。然而，如果谨慎使用，通知可以提供一个非常有价值的推广工具。秘诀在于允许用户选择加入和退出各种消息流，这样他们只接收他们感兴趣的通知。

## 创建模式

考虑到我们的三明治制作应用，似乎很少有发送通知的机会。如果我们要提供让客户除了外卖还可以取三明治的选项，那么用户可能会感激在他们的三明治准备好时收到通知。

为了在设备间有效通信，我们需要一个带有相关应用程序的中心服务器。我们在这里无法涵盖这一点，但这不会阻止我们了解模式的工作原理以及如何发布通知。

我们将从构建一个简单的观察者模式开始，以及一个基本的通知管理器来跟踪和报告订单进度。

要了解如何执行此操作，请按照以下步骤操作：

1.  观察者模式的核心是一个用于主体的接口和一个用于观察者的接口。

1.  主体接口如下所示：

    ```kt
    public interface Subject { 

        void register(Observer o); 
        void unregister(Observer o); 
        boolean getReady(); 
        void setReady(boolean b); 
    } 

    ```

1.  这是观察者接口：

    ```kt
    public interface Observer { 

        String update(); 
    } 

    ```

1.  接下来，将正在订购的三明治实现为主体，如下所示：

1.  接下来，像这样实现观察者接口：

    ```kt
    public class Sandwich implements Subject { 
        public boolean ready; 

        // Maintain a list of observers 
        private ArrayList<Observer> orders = new ArrayList<Observer>(); 

        @Override 
        // Add a new observer 
        public void register(Observer o) { 
            orders.add(o); 
        } 

        @Override 
        // Remove observer when order complete 
        public void unregister(Observer o) { 
            orders.remove(o); 
        } 

        @Override 
        // Update all observers 
        public void notifyObserver() { 
            for (Observer order : orders) { 
                order.update(); 
            } 
        } 

        @Override 
        public boolean getReady() { 
            return ready; 
        } 

        public void setReady(boolean ready) { 
            this.ready = ready; 
        } 
    } 

    ```

    ```kt
    public class Order implements Observer { 
        private Subject subject = null; 

        public Order(Subject subject) { 
            this.subject = subject; 
        } 

        @Override 
        public String update() { 

            if (subject.getReady()) { 

                // Stop receiving notifications 
                subject.unregister(this); 

                return "Your order is ready to collect"; 

            } else { 
                return "Your sandwich will be ready very soon"; 
            } 
        } 
    } 

    ```

    这完成了模式本身；其结构非常简单，如下所示：

    ![创建模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_002.jpg)

在这里，主体完成所有工作。它保存了所有观察者的列表，并为观察者提供订阅和取消订阅更新的机制。在前一个示例中，我们从观察者中在`update()`时调用`unregister()`，一旦订单完成，因为我们的监听器将不再对此主体感兴趣。

`Observer`接口看起来可能过于简单而不必要，但它允许`Sandwich`与其观察者之间进行松耦合，这意味着我们可以独立修改它们中的任何一个。

尽管我们只包含了一个观察者，但应该清楚的是，我们在主体中实现的方法允许任何数量的单独订单并相应地响应。

## 添加通知

`order.update()`方法为我们提供了适当的通知文本。要测试该模式并将通知发送到状态栏，请按照以下步骤操作：

1.  首先，创建一个包含以下嵌套布局的 XML 布局：

    ```kt
    <LinearLayout 
        ... 
        android:layout_alignParentBottom="true" 
        android:layout_centerHorizontal="true" 
        android:gravity="end" 
        android:orientation="horizontal"> 

        <Button 
            android:id="@+id/action_save" 
            style="?attr/borderlessButtonStyle" 
            android:layout_width="wrap_content" 
            android:layout_height="wrap_content" 
            android:minWidth="64dp" 
            android:onClick="onOrderClicked" 
            android:padding="@dimen/action_padding" 
            android:text="ORDER" 
            android:textColor="@color/colorAccent" 
            android:textSize="@dimen/action_textSize" /> 

        <Button 
            android:id="@+id/action_update" 
            ... 
            android:onClick="onUpdateClicked" 
            android:padding="@dimen/action_padding" 
            android:text="UPDATE" 
            ... 
            /> 

    </LinearLayout> 

    ```

1.  打开你的 Java 活动并添加这些字段：

    ```kt
    Sandwich sandwich = new Sandwich(); 
    Observer order = new Order(sandwich); 

    int notificationId = 1; 

    ```

1.  添加监听订单按钮被点击的方法：

    ```kt
    public void onOrderClicked(View view) { 

        // Subscribe to notifications 
        sandwich.register(order); 
        sendNotification(order.update()); 
    } 

    ```

1.  为更新按钮添加一个：

    ```kt
    public void onUpdateClicked(View view) { 

        // Mimic message from server 
        sandwich.setReady(true); 
        sendNotification(order.update()); 
    } 

    ```

1.  最后，添加`sendNotification()`方法：

```kt
private void sendNotification(String message) { 

    NotificationCompat.Builder builder = 
            (NotificationCompat.Builder) 
            new NotificationCompat.Builder(this) 
                    .setSmallIcon(R.drawable.ic_stat_bun) 
                    .setContentTitle("Sandwich Factory") 
                    .setContentText(message); 

    NotificationManager manager = (NotificationManager) 
            getSystemService(NOTIFICATION_SERVICE); 
    manager.notify(notificationId, builder.build()); 

    // Update notifications if needed 
    notificationId += 1; 
} 

```

我们现在可以在设备或模拟器上运行代码：

![添加通知](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_003.jpg)

上面的代码负责发送通知，它展示了发布通知的最简单方式，其中图标和两个文本字段是此操作的最小要求。

### 注意

由于这只是一个演示，观察者模式实际上所做的并不比模拟服务器更多，因此重要的是不要将其与原生的通知 API 调用混淆。

通知 ID 的使用值得注意。这主要用于更新通知。使用相同的 ID 发送通知将更新之前的消息，在前面提到的情况下，实际上我们应该这样做，这里 ID 的递增只是为了演示如何使用它。为了纠正这一点，注释掉该行并重新运行项目，以便只生成一个消息流。

我们还可以并且应该做更多的事情来充分利用这个宝贵的工具，例如在应用不活跃时执行操作并传递通知，我们将在后面的章节回到这些问题，但现在看看 Java 如何提供自己的工具来实现观察者模式是值得的。

## 实用观察者和可观察对象

如前所述，Java 提供了自己的观察者工具，即`java.util.observer`接口和`java.util.observable`抽象类。它们配备了注册、注销和通知观察者的方法。正如通过以下步骤可以看到的，前一个示例可以很容易地使用它们实现：

1.  在这个例子中，主题是通过扩展可观察类来实现的，如下所示：

    ```kt
    import java.util.Observable; 

    public class Sandwich extends Observable { 
        private boolean ready; 

        public Sandwich(boolean ready) { 
            this.ready = ready; 
        } 

        public boolean getReady() { 
            return ready; 
        } 

        public void setReady(boolean ready) { 
            this.ready = ready; 
            setChanged(); 
            notifyObservers(); 
        } 
    } 

    ```

1.  `Order`类是一个观察者，因此实现了这个接口，如下所示：

    ```kt
    import java.util.Observable; 
    import java.util.Observer; 

    public class Order implements Observer { 
        private String update; 

        public String getUpdate() { 
            return update; 
        } 

        @Override 
        public void update(Observable observable, Object o) { 
            Sandwich subject = (Sandwich) observable; 

            if (subject.getReady()) { 
                subject.deleteObserver(this); 
                update = "Your order is ready to collect"; 

            } else { 
                update = "Your sandwich will be ready very soon"; 
            } 
        } 
    } 

    ```

1.  XML 布局和`sendNotification()`方法与之前完全相同，活动中源代码唯一的变化如下所述：

    ```kt
    public class MainActivity extends AppCompatActivity { 
        Sandwich sandwich = new Sandwich(false); 
        Order order = new Order(); 
        private int id; 

        @Override 
        protected void onCreate(Bundle savedInstanceState) 
            { ... } 

        public void onOrderClicked(View view) { 
            sandwich.addObserver(order); 
            sandwich.setReady(true); 
            sendNotification(order.getUpdate()); 
        } 

        public void onUpdateClicked(View view) { 
            sandwich.setReady(true); 
            sendNotification(order.getUpdate()); 
        } 

        private void sendNotification(String message) 
            { ... } 
    } 

    ```

如你所见，这段代码执行的任务与我们的前一个示例相同，值得比较这两个清单。观察者的`setChanged()`和`notifyObservers()`方法替换了我们自定义版本中实现的方法。

你未来采用哪种观察者模式的方法主要取决于特定情况。通常，Java 可观察工具适用于简单情况，如果你不确定，从这种方法开始是个好主意，因为很快你就会看到是否需要更灵活的方法。

以上示例仅介绍了观察者模式和通知。该模式展示了一个非常简单的情况，为了充分发挥其潜力，我们需要将其应用于更复杂的情况。不过首先，我们会看看我们还能用通知系统做些什么。

# 通知

向用户发送简单的字符串消息是通知系统的主要目的，但它还能做更多的事情。首先，通知可以被设置为执行一个或多个操作；通常其中之一是打开相关的应用程序。也可以创建扩展的通知，其中可以包含各种媒体，这对于单行消息无法容纳过多信息的情况非常有用，但我们又想省去用户打开应用程序的麻烦。

从 API 21 开始，已经可以发送弹窗通知和用户锁屏上的通知。这个功能是从其他移动平台上借鉴来的，尽管它显然很有用，但应该谨慎使用。几乎不用说，通知应该只包含相关及时的信息。经验法则是，只有在信息不能等到用户下次登录时才能发出通知。一个有效的通知的例子可能是*你的三明治已经延迟了*，而不是*新款奶酪即将推出*。

除了可能打扰用户的风险，锁屏通知还包含另一个危险。在锁定设备上显示的消息对于所有意图和目的都是公开的。任何经过留在桌上的手机的人都能看到内容。现在尽管大多数人可能不介意他们的老板看到他们喜欢的三明治类型，毫无疑问，你将编写的一些应用程序将包含更敏感的材料，幸运的是 API 提供了可编程的隐私设置。

尽管需要谨慎使用，但通知功能的完整范围仍然值得熟悉，从让通知实际执行某些操作开始。

## 设置意图

与启动活动或其他任何顶级应用组件一样，意图为我们提供了从通知到操作的路径。在大多数情况下，我们希望使用通知来启动活动，这就是我们在这里要做的事情。

移动设备的用户希望能够在活动和应用程序之间轻松快速地移动。当用户在应用程序之间导航时，系统会跟踪其顺序并将其存储在返回栈中。这通常已经足够，但是当用户被通知从应用程序中引开，然后按下返回按钮时，他们不会返回之前参与的应用程序。这很可能会激怒用户，但幸运的是，通过创建一个人工的返回栈可以轻松避免这个问题。

创建我们自己的返回栈并不像听起来那么困难，以下示例证明了这一点。实际上它非常简单，这个例子还详细介绍了如何包含一些其他通知功能，例如更详细的通知图标和当通知首次送达时在状态栏上滚动的提示文本。

按照以下步骤了解如何实现这一点：

1.  打开我们之前工作的项目，并创建一个新的活动类，如下所示：

    ```kt
    public class UserProfile extends AppCompatActivity { 

        @Override 
        protected void onCreate(Bundle savedInstanceState) { 
            super.onCreate(savedInstanceState); 
            setContentView(R.layout.activity_profile); 
        } 
    } 

    ```

1.  接下来，我们需要一个布局文件以匹配之前在`onCreate()`方法中设置的内容视图。这可以留空，只需包含一个根布局。

1.  现在在主活动中的`sendNotification()`方法顶部添加以下行：

    ```kt
    Intent profileIntent = new Intent(this, UserProfile.class); 

    TaskStackBuilder stackBuilder = TaskStackBuilder.create(this); 
    stackBuilder.addParentStack(UserProfile.class); 
    stackBuilder.addNextIntent(profileIntent); 

    PendingIntent pendingIntent = stackBuilder.getPendingIntent(0, 
            PendingIntent.FLAG_UPDATE_CURRENT); 

    ```

1.  在通知构建器中添加这些设置：

    ```kt
    .setAutoCancel(true) 
    .setTicker("the best sandwiches in town") 
    .setLargeIcon(BitmapFactory.decodeResource(getResources(), 
            R.drawable.ic_sandwich)) 
    .setContentIntent(pendingIntent); 

    ```

1.  最后，在清单文件中包含新的活动：

    ```kt
    <activity android:name="com.example.kyle.ordertracker.UserProfile"> 

        <intent-filter> 
            <action android:name="android.intent.action.DEFAULT" /> 
        </intent-filter> 

    </activity> 

    ```

这些更改的效果是显而易见的：

![设置意图](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_004.jpg)

注释掉生成回退堆栈的行，并在使用另一个应用时打开通知，以了解它如何保持直观的导航。`setAutoCancel()`的调用意味着当跟随通知时，状态栏图标会被取消。

通常，我们希望用户从通知中打开我们的应用，但从用户的角度来看，最重要的是以最少的努力完成任务，如果他们不需要打开另一个应用就能获取相同的信息，那么这是件好事。这就是扩展通知的作用所在。

## 定制和配置通知

扩展通知是在 API 16 中引入的。它提供了一个更大、更灵活的内容区域，与其他移动平台保持一致。扩展通知有三种样式：文本、图像和列表。以下步骤将演示如何实现每一种样式：

1.  下一个项目可以从我们之前使用的项目修改，或者从头开始。

1.  编辑主布局文件，使其包含以下三个按钮和观察者方法：

    ```kt
    android:onClick="onTextClicked" 
    android:onClick="onPictureClicked" 
    android:onClick="onInboxClicked" 

    ```

1.  对`sendNotification()`方法进行以下更改：

    ```kt
    private void sendNotification(NotificationCompat.Style style) { 

        ... 

        NotificationCompat.Builder builder = (NotificationCompat.Builder) new NotificationCompat.Builder(this) 

                .setStyle(style) 

                ... 

        manager.notify(id, builder.build()); 
    } 

    ```

1.  现在创建三种样式方法。首先是大型文本样式：

    ```kt
    public void onTextClicked(View view) { 
        NotificationCompat.BigTextStyle bigTextStyle = new NotificationCompat.BigTextStyle(); 

        bigTextStyle.setBigContentTitle("Congratulations!"); 
        bigTextStyle.setSummaryText("Your tenth sandwich is on us"); 
        bigTextStyle.bigText(getString(R.string.long_text)); 

        id = 1; 
        sendNotification(bigTextStyle); 
    } 

    ```

1.  大图片样式需要以下设置：

    ```kt
    public void onPictureClicked(View view) { 
        NotificationCompat.BigPictureStyle bigPictureStyle = new NotificationCompat.BigPictureStyle(); 

        bigPictureStyle.setBigContentTitle("Congratulations!"); 
        bigPictureStyle.setSummaryText("Your tenth sandwich is on us"); 
        bigPictureStyle.bigPicture(BitmapFactory.decodeResource(getResources(), R.drawable.big_picture)); 

        id = 2; 
        sendNotification(bigPictureStyle); 
    } 

    ```

1.  最后添加列表样式或收件箱样式，如下所示：

```kt
public void onInboxClicked(View view) { 
    NotificationCompat.InboxStyle inboxStyle = new NotificationCompat.InboxStyle(); 

    inboxStyle.setBigContentTitle("This weeks most popular sandwiches"); 
    inboxStyle.setSummaryText("As voted by you"); 

    String[] list = { 
            "Cheese and pickle", 
            ... 
    }; 

    for (String l : list) { 
        inboxStyle.addLine(l); 
    } 

    id = 3; 
    sendNotification(inboxStyle); 
} 

```

这些通知现在可以在设备或 AVD 上进行测试：

![定制和配置通知](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_005.jpg)

最新的通知将始终展开，其他通知可以通过向下轻扫来展开。与大多数材料列表一样，可以通过水平轻扫来消除通知。

这些功能在通知设计上为我们提供了很大的灵活性，如果我们想要做更多，甚至可以自定义它们。通过向构建器传递一个 XML 布局，可以非常简单地完成此操作。为此，我们需要 RemoteViews 类，它是一种布局填充器。创建一个布局，然后在代码中包含以下行以实例化它：

```kt
RemoteViews expandedView = new RemoteViews(this.getPackageName(), R.layout.notification); 

```

然后将其传递给构建器：

```kt
builder.setContent(expandedView); 

```

在实现 Android 通知方面，我们需要了解的是如何发出弹窗通知和锁定屏幕通知。这更多的是关于设置优先级和用户权限及设置，而不是编码。

## 可见性和优先级

通知显示的位置和方式通常取决于两个相关属性：隐私和重要性。这些是通过元数据常量应用的，也可以包括如*闹钟*和*促销*等类别，系统可以使用这些类别对多个通知进行排序和过滤。

当涉及到向用户锁屏发送通知时，不仅是我们如何设置元数据，还取决于用户的安全设置。为了查看这些通知，用户必须选择一个安全的锁，如 PIN 码或手势，然后在**安全 | 通知**设置中选择以下选项之一：

![可见性和优先级](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_006.jpg)

只要用户设置了这些选项，我们的通知就会被发送到用户的锁屏。为了保护用户的隐私，我们可以通过构建器设置通知的可见性。有三个值可供选择：

+   `VISIBILITY_PUBLIC` - 显示整个通知

+   `VISIBILITY_PRIVATE` - 显示标题和图标但隐藏内容

+   `VISIBILITY_SECRET` - 完全不显示任何内容

要实现这些设置之一，请使用如下代码行：

```kt
builder.setVisibility(NotificationCompat.VISIBILITY_PUBLIC) 

```

顶部提醒会在屏幕顶部以基本（折叠）通知的形式出现五秒钟，然后恢复到状态栏图标，以此来提醒用户其重要性。它们只应用于需要用户立即注意的信息。这是通过优先级元数据控制的。

默认情况下，每个通知的优先级是 PRIORITY_DEFAULT。五个可能的值分别是：

+   `PRIORITY_MIN` = -2

+   `PRIORITY_LOW` = -1

+   `PRIORITY_DEFAULT` = 0

+   `PRIORITY_HIGH` = 1

+   `PRIORITY_MAX` = 2

这些也可以通过构建器设置，例如：

```kt
builder.setPriority(NotificationCompat.PRIORITY_MAX) 

```

任何大于 DEFAULT 的值都会触发顶部提醒，前提是同时触发声音或振动。这也可以通过我们的构建器添加，形式如下：

```kt
builder.setVibrate(new long[]{500, 500, 500}) 

```

振动器类接收一个长整型数组，并将其作为毫秒级的振动脉冲，因此前面的例子会振动三次，每次半秒钟。

在应用中的任何位置包含设备振动都需要在安装时获得用户权限。这些权限会作为根元素的直接子元素添加到清单文件中，如下所示：

```kt
<manifest  
    package="com.example.yourapp"> 

    <uses-permission  
        android:name="android.permission.VIBRATE" /> 

    <application 

        ... 

    </application> 

</manifest> 

```

关于显示和配置通知，我们还需要了解的并不多。然而，到目前为止，我们一直在应用内部发出通知，而不是像在野外那样远程发出。

# 服务

服务是顶级应用组件，如活动。它们的目的是管理长时间运行的背景任务，如播放音频或触发提醒或其他计划事件。服务不需要 UI，但在其他方面与活动类似，具有类似的生命周期和相关的回调方法，我们可以使用它们来拦截关键事件。

尽管所有服务一开始都是相同的，但它们基本上分为两类：绑定和非绑定。与活动绑定的服务将继续运行，直到收到停止指令或绑定活动停止。而非绑定的服务，无论调用活动是否活跃，都会继续运行。在这两种情况下，服务通常负责在完成分配的任务后自行关闭。

下面的示例演示了如何创建一个设置提醒的服务。该服务会在设定的延迟后发布通知，或者由用户操作取消。要了解如何实现这一点，请按照以下步骤操作：

1.  首先创建一个布局。这将需要两个按钮：![Services](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_09_007.jpg)

1.  在两个按钮中都包含 onClick 属性：

    ```kt
    android:onClick="onReminderClicked" 
    android:onClick="onCancelClicked" 

    ```

1.  创建一个新的类来扩展 Service：

    ```kt
    public class Reminder extends Service 

    ```

1.  `onBind()`方法虽然会被要求实现，但我们不需要它，所以可以像这样保留：

    ```kt
    @Override 
    public IBinder onBind(Intent intent) { 
        return null; 
    } 

    ```

1.  我们不会使用`onCreate()`或`onDestroy()`方法，但是了解后台活动的行为总是有用的，所以像这样完成方法：

    ```kt
    @Override 
    public void onCreate() { 
        Log.d(DEBUG_TAG, "Service created"); 
    } 

    @Override 
    public void onDestroy() { 
        Log.d(DEBUG_TAG, "Service destroyed"); 
    } 

    ```

1.  该类将需要以下字段：

    ```kt
    private static final String DEBUG_TAG = "tag"; 
    NotificationCompat.Builder builder; 
    @Override 
    public int onStartCommand(Intent intent, int flags, int startId) { 
        Log.d(DEBUG_TAG, "Service StartCommand"); 

        // Build notification 
        builder = new NotificationCompat.Builder(this) 
                .setSmallIcon(R.drawable.ic_bun) 
                .setContentTitle("Reminder") 
                .setContentText("Your sandwich is ready to collect"); 

        // Issue timed notification in separate thread 
        new Thread(new Runnable() { 

            @Override 
            public void run() { 
                Timer timer = new Timer(); 
                timer.schedule(new TimerTask() { 

                    @Override 
                    public void run() { 
                        NotificationManager manager = (NotificationManager) 
                                getSystemService(NOTIFICATION_SERVICE); 
                        manager.notify(0, builder.build()); 
                        cancel(); 
                    } 

                // Set ten minute delay 
                }, 1000 * 60 * 10); 

                // Destroy service after first use 
                stopSelf(); 
            } 

        }).start(); 

        return Service.START_STICKY; 
    } 

    ```

1.  将服务添加到清单文件中，与您的活动并列，如下所示：

    ```kt
    <service 
        android:name=".Reminder" /> 

    ```

1.  最后，打开您的 main Java 活动，并完成这两个按钮的监听器：

    ```kt
    public void onReminderClicked(View view) { 
        Intent intent = new Intent(MainActivity.this, Reminder.class); 
        startService(intent); 
    } 

    public void onCancelClicked(View view) { 
        Intent intent = new Intent(MainActivity.this, Reminder.class); 
        stopService(intent); 
    } 

    ```

上面的代码演示了如何使用服务在后台运行代码。在许多应用程序中，这是一个非常重要的功能。我们唯一真正需要考虑的是确保当不再需要时，所有的服务都能正确地被释放，因为服务特别容易遭受内存泄漏。

# 总结

在本章中，我们看到了观察者模式如何作为一个工具来管理用户通知的传递，以及跟踪许多其他事件并相应地作出反应。我们从模式本身开始，然后了解了 Android 通知 API，尽管它们使用系统控制的状态栏和通知抽屉，但它们在设计和应用通知方面给了我们很大的自由度。

在下一章中，我们将以此和其他模式为例，看看如何扩展现有的 Android 组件，并直接应用我们的设计模式。我们还将了解这在开发除手机和平板电脑以外的其他形态因素时如何帮助我们。


# 第十章：行为模式

到目前为止，在这本书中，我们已经详细研究了许多最重要的创建性和结构性设计模式。这使我们能够构建各种各样的架构，但是为了执行我们所需的任务，这些结构需要能够在自身的元素之间以及与其他结构之间进行通信。

行为模式旨在解决我们在日常开发中遇到的许多通用问题，例如响应特定对象状态的变化或调整行为以适应硬件变化。我们在上一章的观察者模式中已经遇到了一个，在这里我们将进一步了解一些最有用的行为模式。

与创建性和结构性模式相比，行为模式在能够执行的任务类型上具有更高的适应性。虽然这种灵活性很好，但在选择最佳模式时，它也可能使问题复杂化，因为通常会有两三个候选模式可供选择。看看这些模式中的几个，了解它们之间有时微妙的差异，可以帮助我们有效地应用行为模式，这是一个好主意。

在本章中，你将学习如何：

+   创建模板模式

+   向模式中添加专业化层次。

+   应用策略模式

+   构建和使用访问者模式

+   创建一个状态机

这些模式的通用性意味着它们可以应用于大量的不同场景中。它们能够执行的任务类型的一个很好的例子就是点击或触摸监听器，当然还有上一章中的观察者模式。在许多行为模式中经常看到的另一个共同特性是使用抽象类来创建通用算法，正如我们将在本章中看到的**访问者**和**策略模式**以及我们即将探讨的**模板模式**。

# 模板模式

即使你完全不了解设计模式，你也会熟悉模板模式的工作方式，因为它使用抽象类和方法形成一个通用的（模板）解决方案，可以用来创建特定的子类，这正是 OOP 中抽象意图的使用方式。

最简单的模板模式不过是抽象类形式的泛化，至少有一个具体的实现。例如，模板可能定义了一个空的布局，而其实现则控制内容。这种方法的一个很大的优点是，公共元素和共享逻辑只需在基类中定义，这意味着我们只需要在我们实现之间不同的地方编写代码。

如果在基础类中增加一层抽象，模板模式可以变得更加强大和灵活。这些可以作为其父类的子类别，并类似地对待。在探索这些多层次的模式之前，我们将先看一个最简单的基模板例子，它提供了根据其具体实现产生不同输出的属性和逻辑。

一般来说，模板模式适用于可以分解为步骤的算法或任何程序集。这个模板方法在基础类中定义，并通过具体实现来明确。

要理解这个概念，最好的方式是通过例子。这里我们将设想一个简单的新闻源应用，它有一个通用的*故事*模板，以及*新闻*和*体育*的实现。按照以下步骤来创建这个模式：

1.  开始一个新项目，并根据以下组件树创建一个主布局：![模板模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_002.jpg)

1.  创建一个新的抽象类`Story`，作为我们的泛化，如下所示：

    ```kt
            abstract class Story { 
                public String source; 

                // Template skeleton algorithm 
                public void publish(Context context) { 
                    init(context); 
                    setDate(context); 
                    setTitle(context); 
                    setImage(context); 
                    setText(context); 
                } 

                // Placeholder methods 
                protected abstract void init(Context context); 

                protected abstract void setTitle(Context context); 

                protected abstract void setImage(Context context); 

                protected abstract void setText(Context context); 

                // Calculate date as a common property 
                protected void setDate(Context context) { 
                    Calendar calendar = new GregorianCalendar(); 
                    SimpleDateFormat format = 
                         new SimpleDateFormat("MMMM d"); 

                    format.setTimeZone(calendar.getTimeZone()); 

                    TextView textDate = (TextView) 
                        ((Activity) context) 
                        .findViewById(R.id.text_date); 
                    textDate.setText(format.format(calendar.getTime())); 
                } 
            } 

    ```

1.  现在，按照如下方式扩展以创建`News`类：

    ```kt
            public class News extends Story { 
                TextView textHeadline; 
                TextView textView; 
                ImageView imageView; 

                @Override 
                protected void init(Context context) { 
                    source = "NEWS"; 
                    textHeadline = (TextView) ((Activity) context).findViewById(R.id.text_headline); 
                    textView = (TextView) ((Activity) context).findViewById(R.id.text_view); 
                    imageView = (ImageView) ((Activity) context).findViewById(R.id.image_view); 
                } 

                @Override 
                protected void setTitle(Context context) { 
                    ((Activity) context).setTitle(context.getString(R.string.news_title)); 
                } 

                @Override 
                protected void setImage(Context context) { 
                    imageView.setImageResource(R.drawable.news); 
                } 

                @Override 
                protected void setText(Context context) { 
                    textHeadline.setText(R.string.news_headline); 
                    textView.setText(R.string.news_content); 
                } 
            } 

    ```

1.  `Sport`实现是相同的，但有以下例外：

    ```kt
            public class Sport extends Story { 
                ... 

                @Override 
                protected void init(Context context) { 
                    source = "NEWS"; 
                    ... 
                } 

                @Override 
                     protected void setTitle(Context context) { 
                    ((Activity) context).setTitle(context.getString(R.string.sport_title)); 
                } 

                @Override 
                protected void setImage(Context context) { 
                    imageView.setImageResource(R.drawable.sport); 
                } 

                @Override 
                protected void setText(Context context) { 
                    textHeadline.setText(R.string.sport_headline); 
                    textView.setText(R.string.sport_content); 
                } 
            } 

    ```

1.  最后，将这些行添加到主活动中：

    ```kt
    public class MainActivity 
        extends AppCompatActivity 
        implements View.OnClickListener { 

        String source = "NEWS"; 
        Story story = new News(); 

        @Override 
        protected void onCreate(Bundle savedInstanceState) { 
            ... 

            Button button = (Button) 
                findViewById(R.id.action_change); 
            button.setOnClickListener(this); 

            story.publish(this); 
        } 

        @Override 
        public void onClick(View view) { 

            if (story.source == "NEWS") { 
                story = new Sport(); 

            } else { 
                story = new News(); 
            } 

            story.publish(this); 
        } 
    } 

    ```

在真实或虚拟设备上运行这段代码，允许我们在`Story`模板的两个实现之间切换：

![模板模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_003.jpg)

这个模板例子既简单又熟悉，但尽管如此，模板可以应用于许多情况，并为组织代码提供了一种非常方便的方法，特别是当需要定义许多派生类时。类图与代码一样直接：

![模板模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_004.jpg)

## 扩展模板

当各个实现非常相似时，前面的模式非常有用。但通常情况下，我们想要建模的对象虽然彼此足够相似，以至于可以共享代码，但仍然具有不同类型或数量的属性。一个很好的例子可能是阅读图书馆的数据库。我们可以创建一个名为*阅读材料*的基础类，并拥有合适的属性，这可以用来涵盖几乎任何书籍，无论其类型、内容或年龄。然而，如果我们想要包括杂志和期刊，我们可能会发现我们的模型无法表示这类期刊的多样性。在这种情况下，我们可以创建一个全新的基础类，或者创建新的专门抽象类来扩展基础类，而这些类本身也可以被扩展。

我们将使用上面的例子来演示这个更功能性的模板模式。现在这个模型有三个层次：泛化、专化和实现。由于这里重要的是模式的结构，我们将节省时间并使用调试器输出我们实现的对象。要了解如何将其实际应用，请按照以下步骤操作：

1.  首先，创建一个抽象的基类，如下所示：

    ```kt
    abstract class ReadingMaterial { 

        // Generalization 
        private static final String DEBUG_TAG = "tag"; 
        Document doc; 

        // Standardized skeleton algorithm 
        public void fetchDocument() { 
            init(); 
            title(); 
            genre(); 
            id(); 
            date(); 
            edition(); 
        } 

        // placeholder functions 
        protected abstract void id(); 

        protected abstract void date(); 

        // Common functions 
        private void init() { 
            doc = new Document(); 
        } 

        private void title() { 
            Log.d(DEBUG_TAG,"Title : "+doc.title); 
        } 

        private void genre() { 
            Log.d(DEBUG_TAG, doc.genre); 
        } 

        protected void edition() { 
            Log.d(DEBUG_TAG, doc.edition); 
        } 
    } 

    ```

1.  接下来，为书籍类别创建另一个抽象类：

    ```kt
    abstract class Book extends ReadingMaterial { 

        // Specialization 
        private static final String DEBUG_TAG = "tag"; 

        // Override implemented base method 
        @Override 
        public void fetchDocument() { 
            super.fetchDocument(); 
            author(); 
            rating(); 
        } 

        // Implement placeholder methods 
        @Override 
        protected void id() { 
            Log.d(DEBUG_TAG, "ISBN : " + doc.id); 
        } 

        @Override 
        protected void date() { 
            Log.d(DEBUG_TAG, doc.date); 
        } 

        private void author() { 
            Log.d(DEBUG_TAG, doc.author); 
        } 

        // Include specialization placeholder methods 
        protected abstract void rating(); 
    } 

    ```

1.  `Magazine`类应该如下所示：

    ```kt
    abstract class Magazine extends ReadingMaterial { 

        //Specialization 
        private static final String DEBUG_TAG = "tag"; 

        // Implement placeholder methods 
        @Override 
        protected void id() { 
            Log.d(DEBUG_TAG, "ISSN : " + doc.id); 
        } 

        @Override 
        protected void edition() { 
            Log.d(DEBUG_TAG, doc.period); 
        } 

        // Pass placeholder on to realization 
        protected abstract void date(); 
    } 

    ```

1.  现在我们可以创建具体的实现类。首先是书籍类：

    ```kt
    public class SelectedBook extends Book { 

        // Realization 
        private static final String DEBUG_TAG = "tag"; 

        // Implement specialization placeholders 
        @Override 
        protected void rating() { 
            Log.d(DEBUG_TAG, "4 stars"); 
        } 
    } 

    ```

1.  接着是杂志类：

    ```kt
    public class SelectedMagazine extends Magazine { 

        // Realization 
        private static final String DEBUG_TAG = "tag"; 

        // Implement placeholder method only once instance created 
        @Override 
        protected void date() { 
            Calendar calendar = new GregorianCalendar(); 
            SimpleDateFormat format = new SimpleDateFormat("MM-d-yyyy"); 
            format.setTimeZone(calendar.getTimeZone()); 
            Log.d(DEBUG_TAG,format.format(calendar.getTime())); 
        } 
    } 

    ```

1.  创建一个 POJO 作为假数据，如下所示：

    ```kt
    public class Document { 
        String title; 
        String genre; 
        String id; 
        String date; 
        String author; 
        String edition; 
        String period; 

        public Document() { 
            this.title = "The Art of Sandwiches"; 
            this.genre = "Non fiction"; 
            this.id = "1-23456-789-0"; 
            this.date = "06-19-1993"; 
            this.author = "J Bloggs"; 
            this.edition = "2nd edition"; 
            this.period = "Weekly"; 
        } 
    } 

    ```

1.  现在可以通过以下主活动中的代码测试此模式：

```kt
// Print book 
ReadingMaterial document = new SelectedBook(); 
document.fetchDocument(); 

// Print magazine 
ReadingMaterial document = new SelectedMagazine(); 
document.fetchDocument(); 

```

通过更改虚拟文档代码，可以测试任何实现，并将产生如下输出：

```kt
D/tag: The Art of Sandwiches
D/tag: Non fiction
D/tag: ISBN : 1-23456-789-0
D/tag: 06-19-1963
D/tag: 2nd edition
D/tag: J Bloggs
D/tag: 4 stars
D/tag: Sandwich Weekly
D/tag: Healthy Living
D/tag: ISSN : 1-23456-789-0
D/tag: 09-3-2016
D/tag: Weekly

```

上一个例子简短且简单，但它演示了使模式如此有用和多变的每个特性，如下列表详细说明：

+   基类提供标准化的骨架定义和代码，正如`fetchDocument()`方法所展示的。

+   实现中共同的代码在基类中定义，例如`title()`和`genre()`

+   占位符在基类中定义，用于专门的实现，就像`date()`方法的管理方式一样。

+   派生类可以覆盖占位符方法和已实现的方法；请参阅`rating()`

+   派生类可以使用`super`回调到基类，就像`Book`类中的`fetchDocument()`方法一样。

尽管模板模式一开始可能看起来很复杂，但由于有这么多元素是共享的，因此经过深思熟虑的概括和特殊化可以导致具体类中的代码非常简单和清晰，当我们处理的不仅仅是 一个或两个模板实现时，我们会为此感到庆幸。这种在抽象类中定义的代码集中，在模式类图中可以非常清楚地看到，派生类只包含与其单独相关的代码：

![扩展模板](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_005.jpg)

如章节开头所述，在给定情况下通常可以使用多种行为模式，我们之前讨论的模板模式，以及策略模式、访问者模式和状态模式，都适合这个类别，因为它们都是从概括的概要中派生出特殊情况的。这些模式都值得进行一些详细的探讨。

## 策略模式

策略模式与模板模式非常相似，真正的唯一区别在于个体实现创建的时机。模板模式在编译时发生，但策略模式在运行时发生，并且可以动态选择。

策略模式反映变化的发生，其输出取决于上下文，就像天气应用程序的输出取决于位置一样。我们可以在这个演示中使用这个场景，但首先考虑一下策略模式的类图：

![策略模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_007.jpg)

使用天气示例可以轻松实现这一点。打开一个新项目，按照以下步骤查看如何操作：

1.  从策略接口开始；它看起来像这样：

    ```kt
    public interface Strategy { 

        String reportWeather(); 
    } 

    ```

1.  按照这里的类创建几个具体实现：

    ```kt
    public class London implements Strategy { 

        @Override 
        public String reportWeather() { 
            return "Constant drizzle"; 
        } 
    } 

    ```

1.  接下来，创建上下文类，这里就是位置：

    ```kt
    public class Location { 
        private Strategy strategy; 

        public Location(Strategy strategy) { 
            this.strategy = strategy; 
        } 

        public void executeStrategy(Context context) { 
            TextView textView=(TextView) 
                    ((Activity)context) 
                    .findViewById(R.id.text_view); 
            textView.setText(strategy.reportWeather()); 
        } 
    } 

    ```

1.  通过用字符串值模拟位置，我们可以使用以下客户端代码测试该模式：

    ```kt
    Location context; 
    String location = "London"; 

    switch (location) { 
        case "London": 
            context = new Location(new London()); 
            break; 
        case "Glasgow": 
            context = new Location(new Glasgow()); 
            break; 
        default: 
            context = new Location(new Paris()); 
            break; 
    } 

    context.executeStrategy(this); 

    ```

正如这个例子所示，策略模式虽然与模板相似，但用于不同的任务，因为它们分别在运行时和编译时应用。

与此同时，除了应用我们自己的模板和策略外，大多数平台还会将其作为系统的一部分应用。在 Android 框架中，策略模式工作中的一个好例子就是每次设备旋转时，都会应用模板为不同设备安装布局。我们很快就会更详细地了解这一点，但首先还有另外两种模式我们需要检查。

# 访问者模式

与模板和策略模式一样，访问者模式足够灵活，可以执行我们迄今为止考虑的任何任务，与其他行为模式一样，关键在于将正确的模式应用于正确的问题。术语“访问者”可能不如“模板”或“策略”那么不言自明。

访问者模式旨在让客户端可以将一个过程应用于一组不相关对象，而无需关心它们之间的差异。一个现实世界的好例子就是我们去超市购物，可能会购买可以扫描条形码的罐装产品，以及需要称重的新鲜商品。这种差异在超市中不需要我们关心，因为收银员会帮我们处理所有这些事情。在这种情况下，收银员充当访问者，做出关于如何处理单个商品的所有必要决策，而我们（客户端）只需考虑最终的账单。

这并不完全符合我们对“访问者”一词的直观理解，但从设计模式的角度来看，这就是它的含义。另一个现实世界的例子是，如果我们希望穿越城镇。在这个例子中，我们可能会选择出租车或公交车。在这两种情况下，我们只关心最终目的地（也许还有费用），而让司机/访问者协商实际路线的细节。

按照以下步骤，看看如何实现一个访问者模式，以模拟之前概述的超市场景：

1.  开始一个新的 Android 项目，并添加以下接口来定义购物项目，如下所示：

    ```kt
    public interface Item { 

        int accept(Visitor visitor); 
    } 

    ```

1.  接下来，创建两个项目示例。首先是罐装食品：

    ```kt
    public class CannedFood implements Item { 
        private int cost; 
        private String name; 

        public CannedFood(int cost, String name) { 
            this.cost = cost; 
            this.name = name; 
        } 

        public int getCost() { 
            return cost; 
        } 

        public String getName() { 
            return name; 
        } 

        @Override 
        public int accept(Visitor visitor) { 
            return visitor.visit(this); 
        } 
    } 

    ```

1.  接着，添加新鲜食品项目类：

    ```kt
    public class FreshFood implements Item { 
        private int costPerKilo; 
        private int weight; 
        private String name; 

        public FreshFood(int cost, int weight, String name) { 
            this.costPerKilo = cost; 
            this.weight = weight; 
            this.name = name; 
        } 

        public int getCostPerKilo() { 
            return costPerKilo; 
        } 

        public int getWeight() { 
            return weight; 
        } 

        public String getName() { 
            return name; 
        } 

        @Override 
        public int accept(Visitor visitor) { 
            return visitor.visit(this); 
        } 
    } 

    ```

1.  现在我们可以添加访问者接口本身，如下所示：

    ```kt
    public interface Visitor { 

        int visit(FreshFood freshFood); 
        int visit(CannedFood cannedFood); 
    } 

    ```

1.  然后，可以将其实现为以下`Checkout`类：

    ```kt
    public class Checkout implements Visitor { 
        private static final String DEBUG_TAG = "tag"; 

        @Override 
        public int visit(CannedFood cannedFood) { 
            int cost = cannedFood.getCost(); 
            String name = cannedFood.getName(); 
            Log.d(DEBUG_TAG, "Canned " + name + " : " + cost + "c"); 
            return cost; 
        } 

        @Override 
        public int visit(FreshFood freshFood) { 
            int cost = freshFood.getCostPerKilo() * freshFood.getWeight(); 
            String name = freshFood.getName(); 
            Log.d(DEBUG_TAG, "Fresh " + name + " : " + cost + "c"); 
            return cost; 
        } 
    } 

    ```

1.  我们现在可以看到模式如何让我们编写干净的客户端代码，如下所示：

    ```kt
    public class MainActivity extends AppCompatActivity { 
        private static final String DEBUG_TAG = "tag"; 

        private int totalCost(Item[] items) { 
            Visitor visitor = new Checkout(); 
            int total = 0; 
            for (Item item : items) { 
                System.out.println(); 
                total += item.accept(visitor); 
            } 
            return total; 
        } 

        @Override 
        protected void onCreate(Bundle savedInstanceState) { 
            super.onCreate(savedInstanceState); 
            setContentView(R.layout.activity_main); 

            Item[] items = new Item[]{ 
                    new CannedFood(65, "Tomato soup"), 
                    new FreshFood(60, 2, "Bananas"), 
                    new CannedFood(45, "Baked beans"), 
                    new FreshFood(45, 3, "Apples")}; 

            int total = totalCost(items); 
            Log.d(DEBUG_TAG, "Total cost : " + total + "c"); 
        } 
    } 

    ```

    这应该会产生如下输出：

    ```kt
    D/tag: Canned Tomato soup : 65c
    D/tag: Fresh Bananas : 120c
    D/tag: Canned Baked beans : 45c
    D/tag: Fresh Apples : 135c
    D/tag: Total cost : 365

    ```

    访问者模式有两个特别的优势。第一个是它使我们不必使用复杂的条件嵌套来区分项目类型。第二个，也是更重要的优势在于，访问者和被访问者是分开的，这意味着可以添加和修改新的项目类型，而无需对客户端进行任何更改。要了解如何做到这一点，只需添加以下代码：

1.  打开并编辑`Visitor`接口，使其包含如下高亮显示的额外行：

    ```kt
    public interface Visitor { 

        int visit(FreshFood freshFood); 
        int visit(CannedFood cannedFood); 

        int visit(SpecialOffer specialOffer); 
    } 

    ```

1.  按如下方式创建一个`SpecialOffer`类：

    ```kt
    public class SpecialOffer implements Item { 
        private int baseCost; 
        private int quantity; 
        private String name; 

        public SpecialOffer(int cost,  
                            int quantity,  
                            String name) { 
            this.baseCost = cost; 
            this.quantity = quantity; 
            this.name = name; 
        } 

        public int getBaseCost() { 
            return baseCost; 
        } 

        public int getQuantity() { 
            return quantity; 
        } 

        public String getName() { 
            return name; 
        } 

        @Override 
        public int accept(Visitor visitor) { 
            return visitor.visit(this); 
        } 
    } 

    ```

1.  在`Checkout`访问者类中按如下方式重载`visit()`方法：

    ```kt
    @Override 
    public int visit(SpecialOffer specialOffer) { 

        String name = specialOffer.getName(); 
        int cost = specialOffer.getBaseCost(); 
        int number = specialOffer.getQuantity(); 
        cost *= number; 

        if (number > 1) { 
            cost = cost / 2; 
        } 

        Log.d(DEBUG_TAG, "Special offer" + name + " : " + cost + "c"); 
        return cost; 
    } 

    ```

正如所示，访问者模式可以扩展以管理任意数量的项目和任意数量的不同解决方案。访问者可以一次使用一个，或者作为一系列处理过程的一部分，并且通常在导入具有不同格式的文件时使用。

我们在本章中看到的所有行为模式都有非常广泛的应用范围，可以用来解决各种软件设计问题。然而，有一个模式的应用范围甚至比这些还要广泛，那就是状态设计模式或状态机。

# 状态模式

状态模式无疑是所有行为模式中最灵活的一个。该模式展示了我们如何在代码中实现**有限状态机**。状态机是数学家艾伦·图灵的发明，他使用它们来实现通用计算机并证明任何数学上可计算的过程都可以机械地执行。简而言之，状态机可以用来执行我们选择的任何任务。

状态设计模式的工作机制简单而优雅。在有限状态机的生命周期中的任何时刻，该模式都知道其自身的内部状态和当前的外部状态或输入。基于这两个属性，机器将产生一个输出（可能没有）并改变其自身的内部状态（可能相同）。信不信由你，通过适当配置的有限状态机可以实现非常复杂算法。

展示状态模式的传统方式是使用在体育场馆或游乐场可能找到的投币式旋转门作为例子。这有两种可能的状态，锁定和解锁，并接受两种形式的输入，即硬币和物理推力。

要了解如何建模，请按照以下步骤操作：

1.  启动一个新的 Android 项目，并构建一个类似于以下布局的界面：![状态模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_009.jpg)

1.  添加以下接口：

    ```kt
    public interface State { 

        void execute(Context context, String input); 
    } 

    ```

1.  接下来是`Locked`状态：

    ```kt
    public class Locked implements State { 

        @Override 
        public void execute(Context context, String input) { 

            if (Objects.equals(input, "coin")) { 
                Output.setOutput("Please push"); 
                context.setState(new Unlocked()); 

            } else { 
                Output.setOutput("Insert coin"); 
            } 
        } 
    } 

    ```

1.  接着是`Unlocked`状态：

    ```kt
    public class Unlocked implements State { 

        @Override 
        public void execute(Context context, String input) { 

            if (Objects.equals(input, "coin")) { 
                Output.setOutput("You have already paid"); 

            } else { 
                Output.setOutput("Thank you"); 
                context.setState(new Locked()); 
            } 
        } 
    } 

    ```

1.  创建以下单例以保存输出字符串：

    ```kt
    public class Output { 
        private static String output; 

        public static String getOutput() { 
            return output; 
        } 

        public static void setOutput(String o) { 
            output = o; 
        } 
    } 

    ```

1.  接下来添加`Context`类，如下所示：

    ```kt
    public class Context { 
        private State state; 

        public Context() { 
            setState(new Locked()); 
        } 

        public void setState(State state) { 
            this.state = state; 
        } 

        public void execute(String input) { 
            state.execute(this, input); 
        } 
    } 

    ```

1.  最后，编辑主活动以匹配以下代码：

    ```kt
    public class MainActivity extends AppCompatActivity implements View.OnClickListener { 
        TextView textView; 
        Button buttonCoin; 
        Button buttonPush; 

        Context context = new Context(); 

        @Override 
        protected void onCreate(Bundle savedInstanceState) { 
            super.onCreate(savedInstanceState); 
            setContentView(R.layout.activity_main); 

            textView = (TextView) findViewById(R.id.text_view); 

            buttonCoin = (Button) findViewById(R.id.action_coin); 
            buttonPush = (Button) findViewById(R.id.action_push); 
            buttonCoin.setOnClickListener(this); 
            buttonPush.setOnClickListener(this); 
        } 

        @Override 
        public void onClick(View view) { 

            switch (view.getId()) { 

                case R.id.action_coin: 
                    context.execute("coin"); 
                    break; 

                case R.id.action_push: 
                    context.execute("push"); 
                    break; 
            } 

            textView.setText(Output.getOutput()); 
        } 
    } 

    ```

这个例子可能很简单，但它完美地展示了这个模式有多么强大。很容易看出同样的方案如何扩展来模拟更复杂的锁定系统，而有限状态机通常用于实现组合锁。正如前面提到的，状态模式可以用来模拟任何可以数学建模的事物。前面的例子很容易测试，也很容易扩展：

![状态模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_011.jpg)

状态模式的真正魅力不仅在于它极其灵活，而且在于它在概念上的简单性，这一点在类图上可以看得最清楚：

![状态模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_10_013.jpg)

状态模式，就像本章中的所有模式和其他行为模式一样，具有非常高的灵活性，这种能够适应大量情况的能力源于它们的抽象性质。这可能会使得行为模式在概念上更难以掌握，但通过一些尝试和错误是找到适合各种情境的正确模式的好方法。

# 总结

行为模式在结构上可能非常相似，功能上也有很多重叠，本章大部分内容是理论性的，以便我们可以集体地接近它们。一旦我们熟悉了这些结构，我们就会发现自己会经常在许多情况下返回到它们。

在下一章中，我们将专注于更多技术性的事务，并了解如何为各种可用的表单因子开发应用程序，例如手表和电视屏幕。从我们目前完成的工作来看，我们可以发现如何使用访问者模式等模式来管理这些选择。正如我们已经经历过的，系统为我们管理了大部分这些工作，经常使用它自己的内置模式。尽管如此，在设计模式中，我们仍有很多机会简化并合理化我们的代码。


# 第十一章：可穿戴设备模式

迄今为止，在这本书中，我们考虑的所有 Android 应用程序都是为移动设备（如手机和平板电脑）设计的。正如我们所见，框架提供了极大的便利，确保我们的设计能在各种屏幕大小和形状上良好工作。然而，还有三种形态因素是我们至今未涉及的，那就是如手表、车载控制台和电视机等可穿戴设备。

![可穿戴设备模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_001.jpg)

当涉及到将这些设计模式应用于这些替代平台时，我们选择哪种模式取决于应用程序的目的，而不是平台本身。由于我们在上一章中重点讨论了模式，本章将主要涵盖为这些设备类型构建应用程序的实际操作。然而，当我们查看电视应用程序时，会发现它们采用了**模型-视图-呈现者模式**。

由于我们尚未处理编码传感器的部分，章节将包括探索如何读取用户的心率，并让我们的代码对此作出响应。物理传感器（如心率监测器和加速度计）的管理方式非常相似，通过研究其中一个，我们可以了解如何处理其他传感器。

在本章中，你将学习如何：

+   设置电视应用程序

+   使用 leanback 库

+   应用 MVP 模式

+   创建横幅和媒体组件

+   理解浏览器和消费视图

+   连接到可穿戴设备

+   管理可穿戴设备的屏幕形状

+   处理可穿戴设备的通知

+   读取传感器数据

+   理解自动安全特性

+   为媒体服务配置自动应用程序

+   为消息服务配置自动应用程序

在为这个广泛的形态因素开发时，首先要考虑的不仅仅是需要准备图形的大小，还有观看距离。大多数 Android 设备从几英寸远的地方使用，并且经常设计为可旋转、移动和触摸。这里的例外是电视屏幕，通常是从大约 10 英尺远的地方观看。

# 安卓电视

电视通常最适合于观看电影、电视节目和玩游戏等放松活动。然而，在这些活动中仍然有很大的重叠区域，尤其是在游戏方面，许多应用程序可以轻松转换为在电视上运行。观看距离、高清晰度和控制器设备意味着需要做出一些适应，这主要得益于 leanback 支持库的帮助。这个库促进了模型-视图-呈现者（model-view-presenter）设计模式的实现，这是模型-视图-控制器（model-view-controller）模式的一种适应。

对于电视，可以开发各种类型的应用，但其中很大一部分属于两类：游戏和媒体。与通常受益于独特界面和控制的游戏不同，基于媒体的应用通常应使用平台熟悉的和一致的控件和小部件。这就是**leanback 库**发挥作用的地方，它提供了各种详细、浏览器和搜索小部件，以及覆盖层。

![Android TV](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_002.jpg)

leanback 库并不是唯一对电视开发有用的支持库，CardView 和 RecyclerView 也很有用，实际上 RecyclerView 是必需的，因为一些 leanback 类依赖于它。

Android Studio 提供了一个非常实用的电视模块模板，它提供了十几个展示许多基于媒体的电视应用所需功能的类。仔细研究这个模板是非常值得的，因为它是一个相当好的教程。然而，除非项目性质相当通用，否则它不一定是单个项目的最佳起点。如果你计划进行任何原创项目，有必要了解有关如何设置电视项目的一些知识，从设备主屏幕开始。

## 电视主屏幕

主屏幕是 Android TV 用户的入口点。从这里，他们可以搜索内容，调整设置，访问应用和游戏。用户对我们的应用的第一印象将是在这个屏幕上以横幅图像的形式出现。

每个电视应用都有一个横幅图像。这是一个 320 x 180 dp 的位图，应该以简单高效的方式展示我们的应用功能。例如：

![TV home screen](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_003.jpg)

横幅也可以包含丰富多彩的摄影图像，但文本应始终保持粗体并尽量简练。然后可以在项目清单中声明横幅。要了解如何进行此操作，以及如何设置其他与电视应用相关的**清单**属性，请按照以下步骤操作：

1.  开始一个新项目，选择**TV**作为**Target Android Device**，选择**Android TV Activity**作为活动模板。

1.  将你的图像添加到 drawable 文件夹中，并命名为`banner`或类似名称。

1.  打开`manifests/AndroidManifest.xml`文件。

1.  删除以下行：

    ```kt
            android:banner="@drawable/app_icon_your_company" 

    ```

1.  编辑开头的`<application>`节点，包含以下高亮行：

    ```kt
            <application 
                android:allowBackup="true" 
                android:banner="@drawable/banner" 
                android:label="@string/app_name" 
                android:supportsRtl="true" 
                android:theme="@style/Theme.Leanback"> 

    ```

1.  在根`<manifest>`节点中，添加以下属性：

    ```kt
            <uses-feature 
                android:name="android.hardware.microphone" 
                android:required="false" /> 

    ```

最后一个`<uses-feature>`节点不是严格必需的，但它将使你的应用适用于没有内置麦克风的老款电视。如果你的应用依赖于语音控制，那么省略这个属性。

我们还需要为我们的主活动声明一个 leanback 启动器，操作如下：

```kt
<intent-filter> 
  <action 
        android:name="android.intent.action.MAIN" /> 
  <category 
        android:name="android.intent.category.LEANBACK_LAUNCHER" /> 
</intent-filter> 

```

如果您仅针对电视构建应用，那么在 Play 商店的电视部分使您的应用可用需要做的就是这些。然而，您可能正在开发可以在其他设备上玩的游戏等应用程序。在这种情况下，请包含以下条款以使其适用于可以旋转的设备：

```kt
<uses-feature 
    android:name="android.hardware.screen.portrait" 
    android:required="false" /> 

```

在这些情况下，您还应该将`android.software.leanback`设置为`required="false"`，并恢复到材料或*appcompat*主题。

您可能想知道为什么我们将横幅声明从主活动移动到整个应用。这并非绝对必要，我们所做的是将一个横幅应用于整个应用，不管它包含多少个活动。除非您希望每个活动都有不同的横幅，否则这通常是最佳做法。

## 电视模型-视图-呈现器模式

Leanback 库是少数几个直接促进设计模式使用的库之一，即模型-视图-呈现器（MVP）模式，它是模型-视图-控制器（MVC）的衍生物。这两种模式都非常简单和明显，有些人可能会说它们实际上并不真正符合模式的定义。即使您以前从未接触过设计模式，您也可能会应用其中一种或两种*架构*。

我们之前简要介绍了 MVC 和 MVP，但回顾一下，在 MVC 模式中，视图和控制器是分开的。例如，当控制器从用户那里接收输入，比如按钮的点击，它会将此传递给模型，模型执行其逻辑并将这些更新的信息转发给视图，然后视图向用户显示这些更改，依此类推。

MVP 模式结合了视图和控制器两者的功能，成为用户和模型之间的中介。这是我们之前在适配器模式中看到过的，特别是回收视图及其适配器的工作方式。

Leanback 呈现器类也与嵌套的视图持有者一起工作，在 MVP 模式方面，视图可以是任何 Android 视图，模型可以是任何我们选择的 Java 对象或对象集合。这意味着我们可以使用呈现器作为我们选择的任何逻辑和任何布局之间的适配器。

尽管这个系统很自由，但在开始项目开发之前，了解一下电视应用开发中的一些约定是值得的。

## 电视应用结构

大多数媒体电视应用提供有限的功能集，这通常就是所需要的一切。大多数情况下，用户希望：

+   浏览内容

+   搜索内容

+   消费内容

Leanback 库为这些提供了片段类。一个典型的**浏览器视图**由`BrowserFragment`提供，模板通过一个简单的示例演示了这一点，以及一个`SearchFragment`：

![电视应用结构](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_004.jpg)

**消费视图**由`PlaybackOverlayFragment`提供，可能是最简单的视图，包含的元素比 VideoView 和控制按钮多不了多少。

还有一个`DetailsFragment`，它提供特定内容的信息。这个视图的内容和布局取决于主题内容，可以采取你选择的任何形式，常规的材料设计规则同样适用。**设计视图**从消费视图的底部向上滚动：

![电视应用结构](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_005.jpg)

_Leanback_ 库使得将材料设计引入电视设备变得轻而易举。如果你决定使用其他地方的视图，那么适用于其他地方的同材料规则在这里同样适用。在继续之前，值得一提的是背景图片需要在边缘留出 5%的出血区域，以确保它们能够覆盖所有电视屏幕的边缘。这意味着一个 1280 x 720 像素的图片需要是 1408 x 792 像素。

之前，我们介绍了用于启动应用程序的横幅图像，但我们还需要一种方法来引导用户访问个别内容，尤其是熟悉或相关的内容。

## 推荐卡片

安卓电视主屏幕的顶部行是**推荐行**。这允许用户根据他们的观看历史快速访问内容。内容之所以被推荐，可能是因为它是之前观看内容的延续，或者基于用户的观看历史以某种方式相关。

设计推荐卡片时，我们需要考虑的设计因素寥寥无几。这些卡片由图片或大图标、标题、副标题和应用程序图标构成，如下所示：

![推荐卡片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_006.jpg)

在卡片图片的宽高比方面有一定的灵活性。卡片的宽度绝不能小于其高度的 2/3 或超过 3/2。图片内部不能有透明元素，且高度不得小于 176 dp。

### 提示

大面积的白色在许多电视上可能相当刺眼。如果你需要大面积的白色，使用#EEE 而不是#FFF。

如果你查看一下实时安卓电视设置中的推荐行，你会看到每个卡片被选中时，背景图像会发生变化，我们也应该为每个推荐卡片提供背景图像。这些图像必须与卡片上的图像不同，并且是 2016 x 1134 像素，以允许 5%的出血，并确保它们不会在屏幕边缘留下空隙。这些图像也不应有透明部分。

![推荐卡片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_007.jpg)

设计如此大屏幕的挑战为我们提供了机会，可以包含丰富多彩、高质量的图像。在这个尺寸范围的另一端是可穿戴设备，空间极为宝贵，需要完全不同的方法。

# 安卓穿戴

可穿戴 Android 应用由于另一个原因也值得特别对待，那就是几乎所有 Android Wear 应用都作为伴侣应用，并与在用户手机上运行的主模块结合工作。这种绑定是一个有趣且直接的过程，许多移动应用可以通过添加可穿戴组件大大增强功能。另一个使可穿戴设备开发变得非常有趣的特点是，有许多激动人心的新型传感器和设备。特别是，许多智能手表中配备的心率监测器在健身应用中已经证明非常受欢迎。

可穿戴设备是智能设备开发中最激动人心的领域之一。智能手机和其他配备一系列新型传感器的可穿戴设备为开发者开启了无数新的可能性。

在可穿戴设备上运行的应用需要连接到在手机上运行的主应用，最好将其视为主应用的一个扩展。尽管大多数开发者至少能接触到一部手机，但可穿戴设备对于仅用于测试来说可能是一个昂贵的选项，特别是因为我们至少需要两部设备。这是因为方形和圆形屏幕处理方式的不同。幸运的是，我们可以创建带有模拟器的 AVD，并将其连接到真实的手机或平板电脑，或者是虚拟设备。

## 与可穿戴设备配对

要最好地了解圆形和方形屏幕管理的区别，首先为每种屏幕创建一个模拟器：

![与可穿戴设备配对](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_11_08.jpg)

### 提示

还有一个带下巴的版本，但对于编程目的我们可以将其视为圆形屏幕。

您如何配对可穿戴 AVD 取决于您是将其与真实手机还是另一个模拟器配对。如果您使用手机，需要从以下位置下载 Android Wear 应用：

[`play.google.com/store/apps/details?id=com.google.android.wearable.app`](https://play.google.com/store/apps/details?id=com.google.android.wearable.app)

然后找到 `adb.exe` 文件，默认情况下位于 `user\AppData\Local\Android\sdk\platform-tools\`

在此打开命令窗口，并输入以下命令：

```kt
 adb -d forward tcp:5601 tcp:5601 

```

您现在可以启动伴侣应用并按照说明配对设备。

### 注意

您每次连接手机时都需要执行这个端口转发命令。

如果您要将可穿戴模拟器与模拟手机配对，那么您需要一个针对 Google APIs 而不是常规 Android 平台的 AVD。然后您可以下载 `com.google.android.wearable.app-2.apk`。在网上有许多地方可以找到这个文件，例如：[www.file-upload.net/download](http://www.file-upload.net/download)

apk 文件应放在您的 `sdk/platform-tools` 目录中，可以用以下命令安装：

```kt
adb install com.google.android.wearable.app-2.apk

```

现在启动您的可穿戴 AVD，并在命令提示符中输入 `adb devices`，确保两个模拟器都能用类似以下输出显示出来：

```kt
List of devices attached 
emulator-5554   device 
emulator-5555   device

```

输入：

```kt
adb telnet localhost 5554

```

在命令提示符下，其中 `5554` 是手机模拟器。接下来，输入 `adb redir add tcp:5601:5601\.` 现在你可以使用手持式 AVD 上的 Wear 应用连接到手表。

创建 Wear 项目时，你需要包含两个模块，一个用于可穿戴组件，另一个用于手机。

![与可穿戴设备配对](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_009.jpg)

Android 提供了一个 **可穿戴 UI 支持库**，为 Wear 开发者和设计师提供了一些非常有用的功能。如果你使用向导创建了一个可穿戴项目，这将在设置过程中包含。否则，你需要在 `Module: wear` 的 `build.gradle` 文件中包含以下依赖项：

```kt
compile 'com.google.android.support:wearable:2.0.0-alpha3' 
compile 'com.google.android.gms:play-services-wearable:9.6.1' 

```

你还需要在 Module: mobile 构建文件中包含以下这些行：

```kt
wearApp project(':wear') 
compile 'com.google.android.gms:play-services:9.6.1' 

```

## 管理屏幕形状

我们无法提前知道应用将在哪些形状的屏幕上运行，对此有两个解决方案。第一个，也是最明显的，就是为每种形状创建一个布局，这通常是最佳解决方案。如果你使用向导创建了一个可穿戴项目，你会看到模板活动已经包含了这两种形状。

当应用在实际设备或模拟器上运行时，我们仍然需要一种方法来检测屏幕形状，以便知道要加载哪个布局。这是通过 **WatchViewStub** 实现的，调用它的代码必须包含在我们主活动文件的 `onCreate()` 方法中，如下所示：

```kt
@Override 
protected void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 

    final WatchViewStub stub = (WatchViewStub) 
            findViewById(R.id.watch_view_stub); 
    stub.setOnLayoutInflatedListener( 
            new WatchViewStub.OnLayoutInflatedListener() { 

        @Override 
        public void onLayoutInflated(WatchViewStub stub) { 
            mTextView = (TextView) stub.findViewById(R.id.text); 
        } 

    }); 
} 

```

这可以在 XML 中如下实现：

```kt
<android.support.wearable.view.WatchViewStub  

    android:id="@+id/watch_view_stub" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    app:rectLayout="@layout/rect_activity_main" 
    app:roundLayout="@layout/round_activity_main" 
    tools:context=".MainActivity" 
    tools:deviceIds="wear"> 
 </android.support.wearable.view.WatchViewStub> 

```

为每种屏幕形状创建独立布局的替代方法是使用一种本身能感知屏幕形状的布局。这就是 **BoxInsetLayout** 的形式，它会为圆形屏幕调整内边距设置，并且只在该圆圈中最大可能的正方形内定位视图。

BoxInsetLayout 可以像其他任何布局一样使用，作为主 XML 活动中的根 ViewGroup：

```kt
<android.support.wearable.view.BoxInsetLayout 

    android:layout_height="match_parent" 
    android:layout_width="match_parent"> 

    . . .  

</android.support.wearable.view.BoxInsetLayout> 

```

这种方法确实有一些缺点，因为它并不总是能充分利用圆形表盘上的空间，但 BoxInsetLayout 在灵活性方面的不足，通过易用性得到了弥补。在大多数情况下，这根本不是缺点，因为设计良好的 Wear 应用应该只通过简单信息短暂吸引用户的注意力。用户不希望在手表上导航复杂的 UI。我们在手表屏幕上显示的信息应该能够一眼就被吸收，响应动作应该限制在不超过一次点击或滑动。

智能设备的主要用途之一是当用户无法访问手机时接收通知，例如在锻炼时。

## 可穿戴设备通知

在任何移动应用中添加可穿戴通知功能非常简单。回想一下通知是如何从 第九章，*观察模式* 中传递的：

```kt
private void sendNotification(String message) { 

    NotificationCompat.Builder builder = 
            (NotificationCompat.Builder) 
            new NotificationCompat.Builder(this) 
                    .setSmallIcon(R.drawable.ic_stat_bun) 
                    .setContentTitle("Sandwich Factory") 
                    .setContentText(message); 

    NotificationManager manager = 
            (NotificationManager) 
            getSystemService(NOTIFICATION_SERVICE); 
    manager.notify(notificationId, builder.build()); 

    notificationId += 1; 
} 

```

要使通知也发送到配对的穿戴设备，只需将这两行添加到构建器字符串中：

```kt
.extend(new NotificationCompat.WearableExtender() 

.setHintShowBackgroundOnly(true)) 

```

可选的`setHintShowBackgroundOnly`设置允许我们不显示背景卡片而只显示通知。

大多数时候，穿戴设备被用作输出设备，但它也可以作为输入设备，并且当传感器靠近身体时，可以派生出许多新功能，比如许多智能手机中包含的心率监测器。

## 读取传感器

目前大多数智能设备上都配备了越来越多的传感器，智能手表为开发者提供了新的机会。幸运的是，这些传感器编程非常简单，毕竟它们只是另一种输入设备，因此我们使用监听器来*观察*它们。

尽管单个传感器的功能和用途存在很大差异，但读取它们的方式几乎相同，唯一的区别在于它们输出的性质。下面我们将看看许多可穿戴设备上找到的心率监测器：

1.  打开或启动一个 Wear 项目。

1.  打开穿戴模块，并在主活动 XML 文件中添加一个带有 TextView 的 BoxInsetLayout，如下所示：

    ```kt
            <android.support.wearable.view.BoxInsetLayout 

                android:layout_height="match_parent" 
                android:layout_width="match_parent"> 

                <TextView 
                    android:id="@+id/text_view" 
                    android:layout_width="match_parent" 
                    android:layout_height="wrap_content" 
                    android:layout_gravity="center_vertical" />  

            </android.support.wearable.view.BoxInsetLayout> 

    ```

1.  打开穿戴模块中的 Manifest 文件，并在根`manifest`节点内添加以下权限。

    ```kt
            <uses-permission android:name="android.permission.BODY_SENSORS" /> 

    ```

1.  打开穿戴模块中的主 Java 活动文件，并添加以下字段：

    ```kt
            private TextView textView; 
            private SensorManager sensorManager; 
            private Sensor sensor; 

    ```

1.  在活动上实现一个`SensorEventListener`：

    ```kt
            public class MainActivity extends Activity 
                    implements SensorEventListener { 

    ```

1.  实现监听器所需的两个方法。

1.  如下编辑`onCreate()`方法：

    ```kt
            @Override 
            protected void onCreate(Bundle savedInstanceState) { 
                super.onCreate(savedInstanceState); 
                setContentView(R.layout.activity_main); 

                textView = (TextView) findViewById(R.id.text_view); 

                sensorManager = ((SensorManager) 
                        getSystemService(SENSOR_SERVICE)); 
                sensor = sensorManager.getDefaultSensor 
                        (Sensor.TYPE_HEART_RATE); 
            } 

    ```

1.  添加这个`onResume()`方法：

    ```kt
            protected void onResume() { 
                super.onResume(); 

                sensorManager.registerListener(this, this.sensor, 3); 
            } 

    ```

1.  以及这个`onPause()`方法：

    ```kt
            @Override 
            protected void onPause() { 
                super.onPause(); 

                sensorManager.unregisterListener(this); 
            } 

    ```

1.  如下编辑`onSensorChanged()`回调：

    ```kt
            @Override 
            public void onSensorChanged(SensorEvent event) { 
                textView.setText(event.values[0]) + "bpm"; 
            } 

    ```

![读取传感器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_010.jpg)

如你所见，传感器监听器与点击和触摸监听器一样，完全像观察者一样工作。唯一的真正区别是传感器需要显式注册和注销，因为它们默认不可用，并且在完成操作后需要关闭以节省电池。

所有传感器都可以通过传感器事件监听器以相同的方式管理，通常最好在初始化应用时检查每个传感器的存在，方法是：

```kt
 private SensorManager sensorManagerr = (SensorManager) getSystemService(Context.SENSOR_SERVICE); 
    if (mSensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null){ 
      . . . 
    } 
    else { 
    . . .  
} 

```

穿戴设备开启了应用可能性的全新世界，将 Android 带入我们生活的各个方面。另一个例子就是在我们的汽车中使用 Android 设备。

# Android Auto

与 Android TV 一样，Android Auto 可以运行许多最初为移动设备设计的应用。当然，在车载软件中，安全是首要考虑的因素，这也是为什么大多数 Auto 应用主要集中在音频功能上，比如信息和音乐。

### 注意

由于对安全的重视，Android Auto 应用在发布前必须经过严格的测试。

几乎不用说，开发车载应用时安全是首要原则，因此，Android Auto 应用程序几乎都分为两类：音乐或音频播放器和信息传递。

所有应用在开发阶段都需要进行广泛测试。显然，在实车上测试 Auto 应用是不切实际且非常危险的，因此提供了 Auto API 模拟器。这些可以从 SDK 管理器的工具标签中安装。

![Android Auto](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_11_011.jpg)

## Auto 安全考虑因素

许多关于 Auto 安全的规则都是简单的常识，比如避免动画、分心和延迟，但当然需要对这些进行规范化，谷歌也这样做了。这些规则涉及驾驶员注意力、屏幕布局和可读性。最重要的可以在这里找到：

+   Auto 屏幕上不能有动画元素

+   只允许有声广告

+   应用必须支持语音控制

+   所有按钮和可点击控件必须在两秒内响应

+   文本必须超过 120 个字符，并且始终使用默认的 Roboto 字体

+   图标必须是白色，以便系统控制对比度

+   应用必须支持日间和夜间模式

+   应用必须支持语音命令

+   应用特定按钮必须在两秒内响应用户操作

您可以在以下链接找到详尽的列表：

[developer.android.com/distribute/essentials/quality/auto.html](http://developer.android.com/distribute/essentials/quality/auto.html)

重要提示：在发布之前，谷歌会测试这些以及其他一些规定，因此您自己运行所有这些测试是至关重要的。

### 提示

设计适用于日间和夜间模式的应用，并使系统可以控制对比度，以便在不同光线条件下自动保持可读性，这是一个非常详细的课题，谷歌提供了一个非常有用的指南，可以在以下链接找到：[commondatastorage.googleapis.com/androiddevelopers/shareables/auto/AndroidAuto-custom-colors.pdf](http://commondatastorage.googleapis.com/androiddevelopers/shareables/auto/AndroidAuto-custom-colors.pdf)

除了安全和应用类型的限制之外，Auto 应用与我们所探讨的其他应用在设置和配置上的唯一不同。

## 配置 Auto 应用

如果您使用工作室向导来设置 Auto 应用，您会看到，与 Wear 应用一样，我们必须同时包含移动和 Auto 模块。与可穿戴项目不同，这并不涉及第二个模块，一切都可以从移动模块管理。添加 Auto 组件会提供一个配置文件，可以在`res/xml`中找到。例如：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<automotiveApp> 
    <uses name="media" /> 
</automotiveApp> 

```

对于消息应用，我们会使用以下资源：

```kt
    <uses name="media" /> 

```

通过检查模板生成的清单文件，可以找到其他重要的 Auto 元素。无论您选择开发哪种类型的应用，都需要添加以下元数据：

```kt
<meta-data 
    android:name="com.google.android.gms.car.application" 
    android:resource="@xml/automotive_app_desc" /> 

```

您可以想象，音乐或音频提供者需要伴随启动活动的一个服务，而消息应用则需要一个接收器。音乐服务标签如下所示：

```kt
<service 
    android:name=".SomeAudioService" 
    android:exported="true"> 
    <intent-filter> 
        <action android:name="android.media.browse.MediaBrowserService" /> 
    </intent-filter> 
</service> 

```

对于一个消息应用，我们需要一个服务以及两个接收器，一个用于接收消息，一个用于发送消息，如下所示：

```kt
<service android:name=".MessageService"> 
</service> 

<receiver android:name=".MessageRead"> 
    <intent-filter> 
        <action android:name="com.kyle.someapplication.ACTION_MESSAGE_READ" /> 
    </intent-filter> 
</receiver> 

<receiver android:name=".MessageReply"> 
    <intent-filter> 
        <action android:name="com.kyle.someapplication.ACTION_MESSAGE_REPLY" /> 
    </intent-filter> 
</receiver> 

```

车载设备是 Android 开发中增长最快的领域之一，随着免提驾驶变得越来越普遍，这一领域预计将进一步增长。通常，我们可能只想将单个 Auto 功能集成到主要为其他形态因子设计的应用程序中。

与手持和可穿戴设备不同，我们不必过分关注屏幕尺寸、形状或密度，也不必担心特定车辆的制造商或型号。随着驾驶和交通方式的变化，这无疑将在不久的将来发生变化。

# 总结

本章描述的替代形态因子为开发人员以及我们可以创建的应用类型提供了令人激动的新平台。这不仅仅是针对每个平台开发应用程序的问题，完全有可能在单个应用程序中包含这三种设备类型。

以我们之前看过的三明治制作应用为例；我们可以轻松地调整它，让用户在观看电影时下单三明治。同样，我们也可以将订单准备好的通知发送到他们的智能手机或自动控制台。简而言之，这些设备为新的应用程序和现有应用程序的附加功能开辟了市场。

无论我们的创造多么巧妙或多功能，很少有应用程序不能从社交媒体提供的推广机会中受益。一个单一的*tweet*或*like*可以在不花费广告费用的情况下，触及无数的人。

在下一章中，我们将看到向应用程序中添加社交媒体功能是多么容易，以及我们如何将 Web 应用功能构建到 Android 应用中，甚至使用 SDK 的 webkit 和 WebView 构建完整的 Web 应用。
