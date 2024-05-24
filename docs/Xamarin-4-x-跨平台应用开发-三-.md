# Xamarin 4.x 跨平台应用开发（三）

> 原文：[`zh.annas-archive.org/md5/183290FB388A7F8EC527693139A6FD11`](https://zh.annas-archive.org/md5/183290FB388A7F8EC527693139A6FD11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：联系人、相机和位置

当前移动应用程序最关键的一些特性基于我们的设备可以收集的新类型数据。像 GPS 位置和相机这样的功能是 Instagram 或 Twitter 等现代应用程序的基石。开发一个应用程序而不使用这些功能是非常困难的。因此，让我们探讨使用 Xamarin 利用这一功能的方法。

在本章中，我们将执行以下操作：

+   介绍 Xamarin.Mobile 库

+   在 Android 和 iOS 上读取通讯录

+   获取我们设备的 GPS 位置

+   从相机和照片库中提取照片

# 介绍 Xamarin.Mobile

为了简化这些特性在多个平台上的开发，Xamarin 开发了一个名为 **Xamarin.Mobile** 的库。它为 iOS、Android 甚至 Windows 平台提供了一个单一的 API，用于访问联系人、GPS 位置、屏幕方向、相机和照片库。它还利用 **任务并行库**（**TPL**）提供一个现代的 C# API，使开发者比使用原生替代方案更高效。这使你能够使用 C# 中的 `async` 和 `await` 关键字编写优美、清晰的异步代码。你还可以在 iOS 和 Android 上重用相同的代码，除了 Android 平台所必需的一些差异。

要安装 Xamarin.Mobile，请在 **Xamarin Studio** 中打开 **Xamarin 组件商店**，并将 **Xamarin.Mobile** 组件添加到项目中，如下面的截图所示：

![介绍 Xamarin.Mobile](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00242.jpeg)

在我们深入了解如何使用 Xamarin.Mobile 之前，让我们回顾一下该库提供的命名空间和功能：

+   `Xamarin.Contacts`：这包含了使你能够与完整通讯录交互的类。它包括从联系人的照片、电话号码、地址、电子邮件、网站等所有内容。

+   `Xamarin.Geolocation`：结合加速度计，这可以让你访问设备的 GPS 位置，包括高度、屏幕方向、经度、纬度和速度。你可以明确跟踪设备的位置，或者随着时间的推移监听 GPS 位置的变化。

+   `Xamarin.Media`：这可以访问设备的摄像头（如果设备有多个摄像头）和内置照片库。这是向任何应用程序添加照片选择功能的一种简单方法。

Xamarin.Mobile 是一个开源项目，采用标准的 Apache 2.0 许可证。你可以为项目做贡献或在 GitHub 页面提交问题，地址是[`github.com/xamarin/Xamarin.Mobile`](https://github.com/xamarin/Xamarin.Mobile)。请随意在您的应用程序中使用 Xamarin.Mobile，或者为了自己的目的对其进行分叉和修改。

在本章中，我们将向之前章节构建的 XamSnap 示例应用程序添加许多功能。如有需要，你可能希望访问第六章，*XamSnap for Android*，或者参考本书附带的示例源代码。

# 访问联系人

为了开始探索 Xamarin.Mobile 提供的内容，让我们访问 Xamarin 应用程序内的地址簿。通过从用户的联系人列表加载朋友，来改进 XamSnap 的添加好友功能。确保从组件商店为 iOS 和 Android 项目添加 Xamarin.Mobile。

导航至`XamSnap`可移植类库。首先，我们需要将`IWebService`接口拆分，通过将一个方法移动到新的`IFriendService`接口中：

```kt
public interface IFriendService 
{ 
    Task<User[]> GetFriends(string userName); 
} 

```

接下来，在`FriendViewModel`中，我们需要使用新的`IFriendService`接口而不是旧的接口：

```kt
private IFriendService friendService =  
  ServiceContainer.Resolve<IFriendService>(); 

public async Task GetFriends() 
{ 
  //previous code here, use 'friendService' instead of 'service' 
  Friends = await friendService.GetFriends(settings.User.Name);  
} 

```

现在，我们需要在 iOS 项目中实现`IFriendService`，以便能够从设备的联系人列表中加载。导航至`XamSnap.iOS`项目，并添加一个实现`IFriendService`的新类：

```kt
public class ContactsService : IFriendService 
{ 
  public async Task<User[]> GetFriends(string userName) 
  { 
    var book = new Xamarin.Contacts.AddressBook(); 
    await book.RequestPermission(); 

```

```kt
    var users = new List<User>(); 
    foreach (var contact in book) 
    { 
      users.Add(new User 
      { 
        Name = contact.DisplayName, 
      }); 
    } 
    return users.ToArray();     
  } 
} 

```

要使用 Xamarin.Mobile 加载联系人，你首先必须创建一个`AddressBook`对象。接下来，我们需要调用`RequestPermissions`来请求用户允许访问地址簿。这是一个重要的步骤，因为 iOS 设备要求在应用程序访问用户联系人之前必须这样做。这防止了可能恶意应用在用户不知情的情况下获取联系人。

接下来，我们使用`foreach`遍历`AddressBook`对象，并创建现有应用程序已经理解的`User`对象的实例。这正是 MVVM 设计模式在分层方面的优势的绝佳例子。当我们更换模型层的逻辑时，UI 仍然可以正常工作，无需任何更改。

接下来，我们需要修改我们的`AppDelegate.cs`文件，以使用我们的`ContactsService`作为`IFriendService`接口：

```kt
ServiceContainer.Register<IFriendService>( 
  () => new ContactsService()); 

```

如果在这个时候编译并运行应用程序，你会看到标准的 iOS 弹窗，请求访问联系人，如下面的截图所示：

![访问联系人](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00243.jpeg)

如果你意外点击了**不允许**，可以通过导航到设备上的**设置** | **隐私** | **联系人**来更改此设置。在 iOS 模拟器中，还可以通过关闭应用程序并前往**设置** | **通用** | **重置** | **重置位置与隐私**来重置所有隐私提示。

如果我们的应用程序被授予了正确的访问权限，我们应该能够看到联系人列表，而无需修改应用程序 UI 层的任何代码。以下屏幕截图显示了 iOS 模拟器中的默认联系人列表：

![访问联系人](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00244.jpeg)

## 在 Android 上检索联系人

以非常类似的方式，我们可以使用 Xamarin.Mobile 在 Android 中获取联系人列表。Xamarin.Mobile 中的所有 API 在 Android 上都是相同的，除了在某些地方需要传递`Android.Content.Context`。这是因为许多原生 Android API 需要引用当前活动（或其他如`Application`的上下文）才能正常工作。首先，通过在 Xamarin Studio 中导航到**Android** | **Android Application**创建一个标准的 Android 应用程序项目。确保从组件商店向项目添加 Xamarin.Mobile。

按如下方式添加`IFriendService`的 Android 等效项：

```kt
public class ContactsService : IFriendService 
{ 
  public async Task<User[]> GetFriends(string userName) 
  { 
    var book = new  
        Xamarin.Contacts.AddressBook(Application.Context); 
    await book.RequestPermission(); 

    var users = new List<User>(); 
    foreach (var contact in book) 
    { 
      users.Add(new User 
      { 
        Name = contact.DisplayName, 
      }); 
    } 
    return users.ToArray();     
  } 
} 

```

这段调用 Xamarin.Mobile 的代码与我们为 iOS 编写的代码相同，不同之处在于这里需要为`AddressBook`构造函数中的 Android `Context`传递`Application.Context`。我们的代码修改完成了；但是，如果你现在运行应用程序，将会抛出异常。Android 需要在清单文件中要求权限，这样当从 Google Play 下载时，它会通知用户其访问通讯录的权限。

我们必须修改`AndroidManifest.xml`文件，并按以下方式声明一个权限：

1.  打开 Android 项目的项目选项。

1.  在**构建**下选择**Android Application**标签页。

1.  在**所需权限**部分，勾选**ReadContacts**。

1.  点击**OK**保存更改。

现在如果你运行应用程序，你将获得设备上所有联系人的列表，如下截图所示：

![在 Android 上获取联系人](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00245.jpeg)

# 查找 GPS 位置

使用 Xamarin.Mobile 跟踪用户的 GPS 位置与访问他们的联系人一样简单。iOS 和 Android 设置访问权限的过程类似，但在位置的情况下，你无需从代码请求权限。iOS 会自动显示标准警报请求权限。而 Android 只需要在清单中进行设置。

举个例子，让我们为 XamSnap 应用添加一个功能，在聊天对话中为消息标记 GPS 位置。你可以将其视为像其他应用一样给照片标记位置。确保从组件商店向项目添加 Xamarin.Mobile。

首先，让我们实现一个用于存储纬度和经度的`Location`类：

```kt
public class Location
{
    public double Latitude { get; set; }
    public double Longitude { get; set; }
}
```

接下来，让我们在`Message`类中添加一个`Location`属性：

```kt
public Location Location { get; set; }
```

现在，让我们创建一个新的`ILocationService`接口，用于查询 GPS 位置：

```kt
public interface ILocationService
{
    Task<Location> GetCurrentLocation();
}
```

现在，我们需要更新`MessageViewModel`类，以使用位置服务并在新消息上标记 GPS 位置：

```kt
//As a member variable
private ILocationService locationService = 
  ServiceContainer.Resolve<ILocationService>();
//Then in SendMessage()
var location = await locationService.GetCurrentLocation();
var message = await service.SendMessage(new Message
{
    UserName = settings.User.Name,
    Conversation = Conversation.Id,
    Text = Text,
    Location = location,
});
```

接下来，让我们为 iOS 实现`ILocationService`接口。在 iOS 项目中创建一个新类：

```kt
public class LocationService : ILocationService 
{ 
  private const int Timeout = 3000; 
  private Geolocator _geolocator; 

  public async Task<Location> GetCurrentLocation() 
  { 
    try 
    { 
      //NOTE: wait until here to create Geolocator 
      //  so that the iOS prompt appears on GetCurrentLocation() 
      if (_geolocator == null) 
        _geolocator = new Geolocator(); 

      var location = await _geolocator.GetPositionAsync(Timeout); 

      Console.WriteLine("GPS location: {0},{1}", 
        location.Latitude, location.Longitude); 

      return new Location 
      { 
        Latitude = location.Latitude, 
        Longitude = location.Longitude, 
      }; 
    } 
    catch (Exception exc) 
    { 
      Console.WriteLine("Error finding GPS location: " + exc); 

      //If anything goes wrong, just return null 
      return null; 
    } 
  } 
} 

```

我们在这里所做的首先是在需要时创建一个`Geolocator`对象。这样可以延迟 iOS 权限弹窗，直到你实际去发送消息。然后我们使用`async`/`await`查询 GPS 定位，并设置三秒的超时时间。我们记录找到的位置并创建一个新的`Location`对象，供应用程序的其余部分使用。如果发生任何错误，我们确保记录它们并将我们的`Location`实例返回为`null`。

接下来，在`AppDelegate.cs`中注册我们的新服务：

```kt
ServiceContainer.Register<ILocationService>( 
  () => new LocationService()); 

```

最后，在我们的`Info.plist`文件中有一个设置是 iOS 访问用户位置所必需的，并且它还允许开发者在权限弹窗中显示一条消息。

打开`Info.plist`文件，并按如下所示更改：

1.  点击**源代码**标签。

1.  点击**添加新条目**行上的加号按钮。

1.  在下拉菜单中，选择**使用期间的位置访问描述**。

1.  在**值**字段中为用户输入文本。

如果你编译并运行应用程序，你应该会在添加新消息时看到一个 iOS 权限提示，如下面的截图所示：

![查找 GPS 定位](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00246.jpeg)

如果你观察 Xamarin Studio 中的控制台日志，你将能够看到 GPS 坐标被添加到`Message`对象中。为了实际工作，你将需要部署到物理 iOS 设备上才能看到返回的 GPS 定位。

## 实现 Android 上的 GPS 定位

正如前一部分所述，使用 Xamarin.Mobile 获取 GPS 位置与我们在 iOS 上使用的 API 几乎相同。首先，我们需要像之前一样创建一个`ILocationService`，只需更改一行我们为 iOS 创建的代码：

```kt
if (_geolocator == null) 
  _geolocator = new Geolocator(Application.Context); 

```

然后，在`Application.cs`中注册我们的新服务：

```kt
ServiceContainer.Register<ILocationService>( 
  () => new LocationService()); 

```

同样，这看起来与 iOS 的代码相同，除了`Geolocator`的构造函数。如果在这一点上运行应用程序，它将开始运行且没有错误。然而，`Geolocator`对象不会触发任何事件。我们首先需要从 Android 清单文件中添加访问位置的权限。在`OnResume`中开始定位器，在`OnPause`中停止它也是一个好主意。这将通过在屏幕上不再显示此活动时停止 GPS 定位来节省电池。

让我们创建一个`AndroidManifest.xml`文件，并声明两个权限，如下所示：

1.  打开 Android 项目的项目选项。

1.  在**构建**下选择**Android 应用程序**标签。

1.  点击**添加 Android 清单**。

1.  在**所需权限**部分，勾选**AccessCoarseLocation**和**AccessFineLocation**。

1.  点击**确定**保存你的更改。

现在，如果你编译并运行应用程序，你将获得与新发送的消息关联的 GPS 定位信息。大多数 Android 模拟器都有模拟 GPS 定位的选项。x86 HAXM 模拟器位于底部点菜单下，然后是**扩展控制 | 位置**，如下面的截图所示：

![在 Android 上实现 GPS 定位](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00247.jpeg)

# 访问照片库和相机

Xamarin.Mobile 的最后一个主要功能是访问照片，以使用户能够向你的应用程序添加自己的内容。使用一个名为`MediaPicker`的类，你可以从设备的相机或照片库中获取照片，并可以选择性地为操作显示你自己的 UI。

让我们修改`MessageViewModel`以支持照片。首先，添加以下属性：

```kt
public string Image { get; set; } 

```

接下来，我们需要修改`SendMessage`方法中的以下几行：

```kt
if (string.IsNullOrEmpty(Text) && string.IsNullOrEmpty(Image))
   throw new Exception("Message is blank.");

//Then further down 
var message = await service.SendMessage(new Message
{
     UserName = settings.User.Name,
     Conversation = Conversation.Id,
     Text = Text,
     Image = Image,
     Location = location,
});
//Clear our variables 
Text =
      Image = null;  

```

然后，我们需要修改 UI 层以提示选择照片。打开`MessagesController.cs`并在类的顶部添加以下变量：

```kt
UIBarButtonItem photo; 
MediaPicker picker; 

```

在`ViewDidLoad`方法中，我们需要设置`MediaPicker`和一个新的`UIBarButtonItem`来选择照片：

```kt
picker = new MediaPicker(); 
photo = new UIBarButtonItem(UIBarButtonSystemItem.Camera,  
  (sender, e) => 
  { 
    //In case the keyboard is up 
    message.ResignFirstResponder(); 

    var actionSheet = new UIActionSheet("Choose photo?"); 
    actionSheet.AddButton("Take Photo"); 
    actionSheet.AddButton("Photo Library"); 
    actionSheet.AddButton("Cancel"); 
    actionSheet.Clicked += OnActionSheetClicked; 
    actionSheet.CancelButtonIndex = 2; 
    actionSheet.ShowFrom(photo, true); 
  }); 

```

在这里我们使用`UIActionSheet`类来提示用户决定他们是想拍摄新照片还是打开现有照片。现在让我们实现`OnActionSheetClicked`方法：

```kt
async void OnActionSheetClicked( 
  object sender, UIButtonEventArgs e) 
{ 
  MediaPickerController controller = null; 
  try 
  { 
    if (e.ButtonIndex == 0) 
    { 
      if (!picker.IsCameraAvailable) 
      { 
        new UIAlertView("Oops!",  
          "Sorry, camera not available on this device!", null,  
          "Ok").Show(); 
        return; 
      } 

      controller = picker.GetTakePhotoUI( 
        new StoreCameraMediaOptions()); 
      PresentViewController(controller, true, null); 

      var file = await controller.GetResultAsync(); 
      messageViewModel.Image = file.Path; 
      Send(); 
    } 
    else if (e.ButtonIndex == 1) 
    { 
      controller = picker.GetPickPhotoUI(); 
      PresentViewController(controller, true, null); 

      var file = await controller.GetResultAsync(); 
      messageViewModel.Image = file.Path; 
      Send(); 
    } 
  } 
  catch (TaskCanceledException) 
  { 
    //Means the user just cancelled 
  } 
  finally 
  { 
    controller?.DismissViewController(true, null); 
  } 
} 

```

使用`MediaPicker`非常直接；你只需调用`GetTakePhotoUI`或`GetPickPhotoUI`来获取一个`MediaPickerController`实例。然后，你可以调用`PresentViewController`以模态形式在当前控制器顶部显示控制器。调用`GetResultAsync`之后，我们使用结果`MediaFile`对象将照片路径传递给我们的 ViewModel 层。还需要使用`try-catch`块，以防用户取消并调用`DismissViewController`隐藏模态界面。

接下来，我们需要修改`UITableViewSource`以显示照片：

```kt
public override UITableViewCell GetCell( 
  UITableView tableView, NSIndexPath indexPath)
  {
     var message = messageViewModel.Messages[indexPath.Row];
     bool isMyMessage = message.UserName == settings.User.Name;
     var cell = tableView.DequeueReusableCell( 
       isMyMessage ? MyCellName : TheirCellName);
     cell.TextLabel.Text = message.Text ?? string.Empty;
     cell.ImageView.Image = string.IsNullOrEmpty(message.Image) ?
       null : UIImage.FromFile(message.Image);
     return cell; 
  }  

```

我们需要处理的最后一个情况是在`ViewWillAppear`方法中：

```kt
//Just after subscribing to IsBusyChanged 
if (PresentedViewController != null) 
  return; 

```

如果我们不进行这项更改，选择照片后照片列表将会刷新，这可能导致一些奇怪的行为。

现在你应该能够运行应用程序并在屏幕上选择照片。以下屏幕截图显示了我从照片库中选择的 iOS 模拟器中的默认照片：

![访问照片库和相机](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00248.jpeg)

## 在 Android 上访问照片

与 iOS 相比，我们在 Android 上需要使用稍微不同的模式从相机或照片库中检索照片。Android 中的一个常见模式是调用`StartActivityForResult`从另一个应用程序启动活动。当此活动完成后，将调用`OnActivityResult`以通知你的活动操作已完成。因此，Xamarin.Mobile 在 Android 上不能使用与 iOS 相同的 API。

首先，让我们修改 Android 的布局以处理照片。在`Messages.axml`中的`EditText`之前添加一个新的`ImageButton`，如下所示：

```kt
<ImageButton 
  android:layout_width="wrap_content" 
  android:layout_height="wrap_content" 
  android:id="@+id/photoButton" 
  android:layout_alignParentLeft="true" 
  android:src="img/ic_menu_camera" /> 

```

然后在`EditText`中添加`android:layout_toRightOf="@+id/photoButton"`属性。

接下来，我们需要按照以下方式修改`MyMessageListItem`和`TheirMessageListItem`：

```kt
<!-MyMessageListItem--> 
<ImageView
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:id="@+id/myMessageImage" />
<TextView   android:text="Message"
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:id="@+id/myMessageText"
   android:layout_margin="3dp"
   android:textColor="@android:color/holo_blue_bright"
   android:layout_toRightOf="@id/myMessageImage" /> 
<!-TheirMessageListItem--> 
<ImageView
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:id="@+id/theirMessageImage" />
<TextView
   android:text="Message"
   android:layout_width="wrap_content"
   android:layout_height="wrap_content"
   android:id="@+id/theirMessageText"
   android:layout_margin="3dp"
   android:textColor="@android:color/holo_green_light"
   android:layout_alignParentRight="true" />  

```

在这两种情况下，修改 Android XML 要容易得多，因为设计师在向现有视图的左右添加新视图时有时会有些挑剔。

现在，让我们在`MessagesActivity.cs`文件的顶部添加几个成员变量，如下所示：

```kt
MediaPicker picker; 
ImageButton photoButton; 
bool choosingPhoto; 

```

接下来，让我们按如下方式重新排列`OnCreate`方法：

```kt
protected override void OnCreate(Bundle savedInstanceState) 
{ 
  base.OnCreate(savedInstanceState); 

  Title = viewModel.Conversation.UserName; 
  SetContentView(Resource.Layout.Messages); 
  listView = FindViewById<ListView>(Resource.Id.messageList); 
  messageText = FindViewById<EditText>(Resource.Id.messageText); 
  sendButton = FindViewById<Button>(Resource.Id.sendButton); 
  photoButton = FindViewById<ImageButton>( 
    Resource.Id.photoButton); 

  picker = new MediaPicker(this); 

  listView.Adapter = 
    adapter = new Adapter(this); 
  sendButton.Click += (sender, e) => Send();

  photoButton.Click += (sender, e) => 
  { 
    var dialog = new AlertDialog.Builder(this) 
      .SetTitle("Choose photo?") 
      .SetPositiveButton("Take Photo", OnTakePhoto) 
      .SetNegativeButton("Photo Library", OnChoosePhoto) 
      .SetNeutralButton("Cancel", delegate { }) 
      .Create(); 
    dialog.Show(); 
  }; 
} 

async void Send() 
{ 
  viewModel.Text = messageText.Text; 
  try 
  { 
    await viewModel.SendMessage(); 
    messageText.Text = string.Empty; 
    adapter.NotifyDataSetInvalidated(); 
  } 
  catch (Exception exc) 
  { 
    DisplayError(exc); 
  } 
} 

```

我们在这里所做的就是当点击`photoButton`时创建一个`AlertDialog`。这与我们在 iOS 上所做的完全相同，为用户提供选项，要么拍照，要么从现有的照片库中选择。我们还把`sendButton`的点击处理程序移到了一个`Send`方法中，这样我们可以重用它。

现在，让我们实现所需的`OnTakePhoto`和`OnChoosePhoto`方法：

```kt
 void OnTakePhoto(object sender, EventArgs e)
 {
     var intent = picker.GetTakePhotoUI(
       new StoreCameraMediaOptions());
     choosingPhoto = true;
     StartActivityForResult(intent, 1);
 }
 void OnChoosePhoto(object sender, EventArgs e)
 {
     var intent = picker.GetPickPhotoUI();
     choosingPhoto = true;
     StartActivityForResult(intent, 1);
 } 

```

在每种情况下，我们都会调用`GetPickPhotoUI`或`GetTakePhotoUI`以获取一个 Android `Intent`对象的实例。这个对象用于在应用程序内启动新的活动。`StartActivityForResult`也会启动`Intent`对象，并期望从新活动中返回一个结果。

接下来，我们需要实现`OnActivityResult`以处理当新活动完成时会发生什么：

```kt
protected async override void OnActivityResult(
  int requestCode, Result resultCode, Intent data)
{
   if (resultCode == Result.Ok)
   {
       var file = await data.GetMediaFileExtraAsync(this);
       viewModel.Image = file.Path;
       Send();
   }
} 

```

如果成功，我们将获取一个`MediaFile`并将它的路径传递给我们的 ViewModel 层。我们调用之前设置的`Send`方法，该方法用于发送消息。

我们还需要在`OnResume`方法中添加以下代码：

```kt
if (choosingPhoto) 
{
   choosingPhoto = false;
   return;
} 

```

这可以防止用户导航到新活动以选择照片然后返回时出现一些奇怪的行为。这和我们之前在 iOS 上需要做的事情非常相似。

为了使这些更改生效，我们需要修改我们的`AndroidManifest.xml`文件，并按如下声明两个权限：

1.  打开 Android 项目的项目选项。

1.  在**构建**下选择**Android 应用程序**标签页。

1.  点击**添加 Android 清单**。

1.  在**所需权限**部分，勾选**相机**和**写入外部存储**。

1.  点击**确定**以保存更改。

你现在应该能够运行应用程序并发送照片作为消息，如下截图所示：

![在 Android 上访问照片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00249.jpeg)

# 概要

在本章中，我们了解了 Xamarin.Mobile 库以及它如何以跨平台的方式加速常见任务。我们从地址簿中检索联系人，并随时间设置 GPS 位置更新。最后，我们从相机和照片库中加载照片。

完成本章后，你应该完全掌握 Xamarin.Mobile 库及其为跨平台开发提供的常见功能。它提供了干净、现代的 API，具有`async`/`await`功能，可以跨 iOS、Android 和 Windows Phone 访问。使用 Xamarin.Mobile 在不同平台上访问联系人、GPS 和照片是非常简单的。

在下一章中，我们将使用 Windows Azure 创建一个真实的网络服务，来驱动我们的 XamSnap 应用程序。我们将使用一个称为 Azure Functions 的功能，并在 iOS 和 Android 上实现推送通知。


# 第九章：带推送通知的 web 服务

现代移动应用程序以其网络连接性为特征。一个不与 web 服务器交互的移动应用既难得一见，也可能是一个无聊的应用。在本书中，我们将使用**Windows Azure**云平台为我们的 XamSnap 应用实现服务器端后端。我们将使用一个名为**Azure Functions**的功能，它非常适合作为我们应用程序的简单后端，并且可以通过**Azure Notification Hubs**发送推送通知。完成这一章节后，我们的 XamSnap 示例应用程序将更接近一个真正的应用程序，并允许其用户相互交互。

本章节，我们将涵盖以下主题：

+   Windows Azure 提供的服务

+   设置你的 Azure 账户

+   Azure Functions 作为 XamSnap 的后端

+   为 XamSnap 实现真实的 web 服务

+   编写客户端代码以调用 Azure Functions

+   使用苹果推送通知服务

+   使用 Google Cloud Messaging 发送通知

# 学习 Windows Azure

Windows Azure 是微软在 2010 年推出的卓越云平台。Azure 提供了**基础设施即服务**（**IaaS**）和**平台即服务**（**PaaS**），用于构建现代的 web 应用程序和服务。这意味着它可以直接为你提供虚拟机的访问，你可以在其中部署任何你选择的操作系统或软件。这称为 IaaS。Azure 还提供了多个用于构建应用程序的平台，如**Azure Web Apps**或**SQL Azure**。这些平台被称为 PaaS，因为你可以在高层次部署软件，并且不需要直接处理虚拟机或管理软件升级。

让我们了解 Windows Azure 提供的以下更常见服务：

+   **虚拟机**：Azure 提供各种规模的虚拟机访问。你可以安装几乎任何你选择的操作系统；Azure 图库中有许多预制的发行版可供选择。

+   **Web Apps**：你可以部署任何类型的网站，这些网站将在 Microsoft **IIS** 中运行，从 ASP .NET 站点到 **PHP** 或 **Node.js**。

+   **SQL Azure**：这是基于云的微软 SQL Server 版本，它是一个功能完整的**区域数据库管理系统**（**RDMS**）用于存储数据。

+   **移动应用**：这是一个用于构建移动应用 web 服务的简单平台。它使用 **SQL Azure** 作为后端存储，并基于 Node.js 的简单 JavaScript 脚本系统来添加业务逻辑。

+   **Azure Functions**：Windows Azure 推出的首款支持新兴“无服务器”架构的产品，这成为了当今的热门词汇。你可以在浏览器中直接使用多种语言开发简单的 API、后台作业、web 钩子等。Azure 会根据传入的请求自动扩展你的函数。

+   **存储**：Azure 提供了**块存储**，用于存储二进制文件，以及**表存储**，这是一种 **NoSQL** 数据持久化解决方案。

+   **服务总线**（Service bus）：这是一个基于云的解决方案，用于创建队列，以便与其他云服务之间的通信提供便利。它还包括通知中心，作为向移动应用提供推送通知的简单方式。

+   **通知中心**（Notification Hubs）：这是一种向 Android、iOS 和 Windows 设备等不同平台发送推送通知的简单方式。

+   **DocumentDB**：一个功能完备的 NoSQL 数据存储，与其他 NoSQL 数据库（如**MongoDB**）相当。

+   **HDInsight**：在 Windows Azure 中运行的 Apache Hadoop 版本，用于管理极大数据集，这也被称为大数据。

除了这些服务外，还有许多正在积极开发的新服务。我们将使用 Azure Functions，并利用 Azure Storage Tables，为 XamSnap 构建我们的 Web 服务。你可以访问[`windowsazure.com`](http://windowsazure.com)了解提供的完整价格和服务列表。

在本书中，我们选择使用 Windows Azure 作为 XamSnap 的 Web 服务后端进行演示，因为它与 C#、Visual Studio 和其他 Microsoft 工具相辅相成。但是，除了 Azure 之外，还有许多其他选择，你可能想要看看。选择 Xamarin 并不会限制你的应用程序可以交互的 Web 服务类型。

下面是一些更常见的服务：

+   **Firebase**：谷歌提供的这项服务与 Azure Mobile Apps 类似，包括数据存储和推送通知等功能。你可以访问[`firebase.google.com`](https://firebase.google.com)了解更多信息。

+   **Urban airship**：这项服务为跨多个平台的移动应用提供推送通知。你可以访问[`urbanairship.com`](http://urbanairship.com)了解更多信息。

+   **亚马逊网络服务**（Amazon Web Services）：这项服务是一个完整的云解决方案，与 Windows Azure 相当。它拥有部署云应用所需的一切，包括完全的虚拟机支持。此外，还有一个名为 **AWS Mobile Hub** 的功能，专门针对移动开发而定制。你可以访问[`aws.amazon.com`](http://aws.amazon.com)获取更多信息。

此外，你可以使用本地 Web 服务器或低成本的托管服务，用你选择的语言和技术开发自己的 Web 服务。

## 设置你的 Azure 账户

要开始使用 Windows Azure 进行开发，你可以订阅一个月的免费试用，并获得 200 美元的 Azure 信用。与此相伴的是，它的许多服务都有免费层级，为你提供性能较低的版本。因此，如果你的试用期结束，你可以根据所使用的服务，继续开发，费用很少或没有。

首先，导航到[`azure.microsoft.com/en-us/free`](http://azure.microsoft.com/en-us/free)，然后执行以下步骤：

1.  点击 **开始免费** 链接。

1.  使用 Windows Live ID 登录。

1.  出于安全考虑，通过你的手机或短信验证你的账户。

1.  输入支付信息。这只在你超出消费限额时使用。在开发你的应用程序时，你不会意外超出预算——通常在真实用户开始与服务互动之前不会意外消费。

1.  勾选**我同意**政策，并点击**注册**。

1.  检查最终设置并点击**提交**。

如果所有必需的信息都正确输入，你现在终于可以访问你的 Azure 账户了。你可以点击页面右上角的**门户**链接来访问你的账户。将来，你可以在 [`portal.azure.com`](http://portal.azure.com) 管理你的 Azure 服务。

Azure 门户使用一组名为 blades 的面板，以便快速导航并深入了解更详细的信息，如下面的屏幕截图所示：

![设置你的 Azure 账户](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00250.jpeg)

这就完成了你的 Windows Azure 注册。与 Apple 和 Google Play 开发者计划相比，这相当简单。随意尝试，但不必太担心花费问题。Azure 大多数服务都有免费版本，并且还提供一定量的免费带宽。你可以访问 [`azure.microsoft.com/en-us/pricing`](http://azure.microsoft.com/en-us/pricing) 获取更多关于定价的信息。

请注意，关于 Windows Azure 价格昂贵的误解很多。你可以在免费层为应用程序进行所有开发而不花一分钱。将应用程序投入生产时，你可以轻松地增加或减少虚拟机实例的数量，以控制成本。通常，如果你没有很多用户，你不会花很多钱。同样，如果你恰好有很多用户，你应该能赚取足够的收入。

# 探索 Azure Functions

对于 XamSnap 的服务器端，我们将使用 Azure Functions 以及 Azure Storage Tables 为应用程序提供后端存储。Azure Functions 是加速服务器端应用程序开发的简单解决方案，可以利用 Windows Azure 的所有功能。我们将使用 .NET 基础类库中的标准 `HttpClient` 类，从 C# 与服务进行交互。

Azure Functions 的几个亮点如下：

+   你可以使用多种编程语言编写函数，如 JavaScript、C#、Python、PHP，以及一些脚本语言，如 Batch、Bash 和 PowerShell

+   Azure Functions 与 Visual Studio Team Services、Bitbucket 和 GitHub 集成，支持**持续集成**（**CI**）场景

+   你可以轻松地使用 Azure Active Directory、Windows Live ID、Facebook、Google 和 Twitter 设置身份验证

+   函数可以通过 HTTP、计划或定时器、Azure 队列等触发

+   Azure Functions 真正实现了无服务器，并且可以动态扩展处理大量数据

你可以了解到为什么 Azure Functions 对于简单的移动应用程序是一个好的选择。加速开发以及它提供的许多特性非常适合我们的 XamSnap 示例应用程序。

在[`portal.azure.com`](http://portal.azure.com)访问你的账户，并执行以下步骤来创建 Azure Function：

1.  点击页面左上角的加号按钮。

1.  通过菜单导航到**计算** | **函数应用**。

1.  输入你选择的域名，比如`yourname-xamsnap`。

1.  选择一个订阅，以便将服务放置在下面。

1.  选择一个现有的**资源组**，或者创建一个新的名为`xamsnap`的资源组。

1.  选择一个**动态应用服务**计划开始。如果你已经有了一个应用服务计划，可以使用现有以**经典**模式运行的计划。

1.  选择一个现有的**存储账户**或创建一个新的。

1.  查看你的最终设置并点击**创建**按钮。

管理门户将显示进度，创建你的 Azure Function App 实例可能需要几秒钟。

让我们创建一个简单的 Hello World 函数来观察其工作情况：

1.  导航到你的 Function App。

1.  点击**快速入门**。

1.  点击选择 C#的**Webhook + API**，然后点击**创建此函数**。

1.  Azure 门户会提供一个快速浏览，如果需要，你可以跳过。

1.  滚动到底部，点击**运行**以查看 Azure Function 的操作。

完成后，你应在日志窗口中看到输出，以及带有`Hello Azure`输出的成功 HTTP 请求。你应该会看到类似于以下截图的内容：

![探索 Azure Functions](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00251.jpeg)

## 创建和调用 Azure Functions

为了开始为 XamSnap 设置后端，我们需要创建一个登录函数。我们还需要实现由应用程序其他部分使用的`IWebService`接口。由于我们的 MVVM 架构，我们应该能够替换当前正在使用的假服务，而不需要更改位于其上的任何层。

返回 Azure 门户，选择你的 Function App 实例，并执行以下步骤：

1.  点击**新建函数**按钮。

1.  选择**空 - C#**模板。

1.  输入`login`作为函数名称。

1.  点击**创建**按钮。

1.  点击**集成**部分。

1.  添加一个带有默认设置的**HTTP**触发器和输出，然后点击**保存**。

1.  添加一个**Azure 表存储**输出，将表名更改为`users`，然后点击**保存**。

现在让我们为我们的函数编写一些代码，切换到**开发**部分，并添加以下代码作为起点：

```kt
#r "Microsoft.WindowsAzure.Storage" 

using System.Net; 
using System.Text; 
using Microsoft.WindowsAzure.Storage.Table; 

private const string PartitionKey = "XamSnap"; 

public static async Task<HttpResponseMessage>  
  Run(HttpRequestMessage req, CloudTable outputTable,  
  TraceWriter log) 
{ 
  dynamic data = await req.Content.ReadAsAsync<object>(); 
  string userName = data?.userName; 
  string password = data?.password; 

  if (string.IsNullOrEmpty(userName) ||  
    string.IsNullOrEmpty(password)) 
  { 
    return new HttpResponseMessage(HttpStatusCode.BadRequest); 
  } 
} 

```

首先，我们添加了对 Azure 存储 SDK 的引用。这是内置的，可供 Azure Functions 使用，我们稍后会用到它。接下来，我们添加了一些 using 语句和一个常量。我们创建了一个静态函数，处理我们之前定义的输入和输出。`req`是 HTTP 输入，`outputTable`是 Azure 表输出。`log`是一个`TraceWriter`，可用于调试和日志记录。最后，我们使用了内置方法将 POST 数据读取到`username`和`password`变量中，以便在我们的函数中使用。

然后，我们需要填充我们功能的剩余部分。将此代码放在我们开始的功能的底部：

```kt
//Let's hash all incoming passwords 
password = Hash(password); 

var operation = TableOperation.Retrieve<User>( 
  PartitionKey, userName); 
var result = outputTable.Execute(operation); 
var existing = result.Result as User; 
if (existing == null) 
{ 
  operation = TableOperation.Insert(new User 
  { 
    RowKey = userName, 
    PartitionKey = PartitionKey, 
    PasswordHash = password, 
  }); 
  result = outputTable.Execute(operation); 

  if (result.HttpStatusCode == (int)HttpStatusCode.Created) 
  { 
    return new HttpResponseMessage(HttpStatusCode.OK); 
  } 
  else 
  { 
    return new HttpResponseMessage( 
      (HttpStatusCode)result.HttpStatusCode); 
  } 
} 
else if (existing.PasswordHash != password) 
{ 
  return new HttpResponseMessage(HttpStatusCode.Unauthorized); 
} 
else 
{ 
  return new HttpResponseMessage(HttpStatusCode.OK); 
} 

```

让我们总结一下我们在前面的 C# 中做了什么：

1.  首先，我们用稍后要添加的函数对传入的密码进行哈希处理。请注意，Azure Functions 有内置的身份验证功能，这对于生产应用来说非常棒。对于我们的示例应用，我们至少采取措施，不将密码以明文形式存储到我们的数据库中。

1.  接下来，我们使用了 Azure 存储 SDK 来检查现有用户。

1.  如果没有结果，我们将继续创建一个新用户。分区键和行键是 Azure 表存储中的概念。在大多数情况下，你会选择一个键来分区你的数据，比如州或邮政编码，而行键是一个唯一的键。对于这个示例，我们只是为分区键使用了一个常量值。

1.  否则，我们比较哈希密码并返回成功。

1.  如果密码不匹配，我们将返回一个未经授权的错误代码。

之后，我们只需要一点代码来定义`Hash`函数和`User`类：

```kt
private static string Hash(string password) 
{ 
  var crypt = new System.Security.Cryptography.SHA256Managed(); 
  var hash = new StringBuilder(); 
  byte[] crypto = crypt.ComputeHash( 
    Encoding.UTF8.GetBytes(password), 0,  
    Encoding.UTF8.GetByteCount(password)); 
  foreach (byte b in crypto) 
  { 
    hash.Append(b.ToString("x2")); 
  } 
  return hash.ToString(); 
} 

public class User : TableEntity 
{ 
  public string PasswordHash { get; set; } 
} 

```

我们使用了`System.Security`命名空间中内置的 SHA-256 哈希算法。这至少比常见的被破解的 MD5 哈希要安全一些。我们还声明了`User`类作为一个表实体，并带有一个额外的列包含哈希。

在这里，只需确保点击**保存**按钮以应用你的更改。Azure Functions 还提供了通过几个源代码控制提供程序为你的脚本提供源代码控制的选项。如果你想在本地的你喜欢的编辑器而不是网站编辑器中更改脚本，可以充分利用这个功能。你应该能够通过以下示例 JSON 测试该功能：

```kt
{ 
  "userName":"test", 
  "password":"password" 
} 

```

要获取 Azure 存储 SDK 的完整文档，请确保查看 MSDN：[`msdn.microsoft.com/en-us/library/azure/mt347887.aspx`](https://msdn.microsoft.com/en-us/library/azure/mt347887.aspx)。

### 在 C# 中使用 HttpClient

我们的 server-side 更改完成后，下一步是在我们的 XamSnap iOS 和 Android 应用程序中实现我们的新服务。幸运的是，由于我们使用了名为`IWebService`的接口，我们只需实现该接口即可在我们的应用程序中使其工作。

现在，通过执行以下步骤，我们可以在 iOS 应用程序中开始设置我们的服务：

1.  打开我们之前在书中创建的`XamSnap.Core`项目。

1.  在项目中创建一个`Azure`文件夹。

1.  创建一个名为`AzureWebService.cs`的新类。

1.  将类设置为`public`并实现`IWebService`。

1.  在你的代码中右键点击`IWebService`，选择**重构** | **实现接口**。

1.  将会出现一行；按**Enter**键以插入方法存根。

当这个设置完成后，你的类看起来会像下面这样：

```kt
public class AzureWebService : IWebService 
{ 
  #region IWebService implementation 

  public Task<User> Login(string username, string password) 
  { 
    throw new NotImplementedException(); 
  } 

  // -- More methods here --  

  #endregion 
} 

```

接下来，我们需要添加对 JSON .NET 库的引用。为此，我们将使用 NuGet 来添加库。右键点击`XamSnap.Core`项目，选择**添加** | **添加包**，并安装 Json .NET。

现在，让我们修改我们的`AzureWebService.cs`文件。为了开始，我们将进行以下更改：

```kt
using System.Net.Http; 
using System.Net.Http.Headers; 
using System.Threading.Tasks; 
using Newtonsoft.Json; 

public class AzureWebService : IWebService 
{ 
  private const string BaseUrl =  
    "https://xamsnap.azurewebsites.net/api/"; 
  private const string ContentType = "application/json"; 
  private readonly HttpClient httpClient = new HttpClient(); 

  // -- Existing code here -- 
} 

```

我们定义了一些 using 语句和几个变量，这些将在这个类中用到。请确保你填写了 Azure Function App 的正确 URL。

接下来，让我们编写一些辅助方法，以简化调用网络请求的过程：

```kt
private async Task<HttpResponseMessage> Post( 
  string url, string code, object obj) 
{ 
  string json = JsonConvert.SerializeObject(obj); 
  var content = new StringContent(json); 
  content.Headers.ContentType =  
    new MediaTypeHeaderValue(ContentType); 

  var response = await httpClient.PostAsync( 
    BaseUrl + url + "?code=" + code, content); 
  response.EnsureSuccessStatusCode(); 
  return response; 
} 

private async Task<T> Post<T>(string url, string code, object obj) 
{ 
  var response = await Post(url, code, obj); 
  string json = await response.Content.ReadAsStringAsync(); 
  return JsonConvert.DeserializeObject<T>(json); 
}} 

```

这段代码的大部分是在 C#中实现调用 RESTful 端点的基础。首先，我们将对象序列化为 JSON，并创建一个带有头部声明为 JSON 的`StringContent`对象。我们用`code`参数格式化 URL，这是 Azure Functions 默认开启的一个简单安全机制。接下来，我们向服务器发送一个 POST 请求，并调用`EnsureSuccessStatusCode`，以便对失败的请求抛出异常。最后，我们添加了第二个方法，将 JSON 响应解析为 C#对象。我们的某些 Azure Functions 将返回数据，所以我们需要这个功能。

现在，让我们按照以下方式实现我们的第一个方法`Login`：

```kt
public async Task<User> Login(string userName, string password) 
{ 
  await Post("login", "key_here", new 
  { 
    userName, 
    password, 
  }); 

  return new User 
  { 
    Name = userName, 
    Password = password, 
  }; 
}} 

```

这非常简单，因为我们已经设置了辅助方法。我们只需要传递我们的函数名称、它的键以及代表我们想要传递给 HTTP 请求的 JSON 的对象。你可以在 Azure Portal 的**开发**部分下的**Function URL**找到所需的键。

接下来，打开`AppDelegate.cs`文件以设置我们的新服务，并添加以下代码：

```kt
//Replace this line 
ServiceContainer.Register<IWebService>( 
  () => new FakeWebService()); 

//With this line 
ServiceContainer.Register<IWebService>( 
  () => new AzureWebService()); 

```

现在，如果你在登录时编译并运行你的应用程序，你的应用应该能够成功调用 Azure Function，并将新用户插入 Azure Table Storage。

### 提示：

如果你正在寻找一个快速管理 Azure Tables 的方法，微软已经发布了一个免费的工具，叫做 Azure Storage Explorer。它适用于 Mac OS X 和 Windows，可以在[`storageexplorer.com`](http://storageexplorer.com)找到。第二个选择是 Visual Studio 中的**Cloud Explorer**，如果你安装了 Azure SDK for .NET，就可以使用。

## 添加更多的 Azure Functions。

我们还需要实现几个方法，用于我们的`IWebService`实现。让我们从添加两个新的 Azure Functions 开始，一个用于获取用户朋友列表，另一个用于添加朋友。

返回 Azure Portal，执行以下步骤：

1.  点击**新建函数**按钮。

1.  选择**Empty - C#**模板。

1.  输入`friends`作为函数名称。

1.  点击**创建**按钮。

1.  点击**集成**部分。

1.  添加一个带有默认设置的**HTTP**触发器和输出，然后点击**保存**。

1.  添加一个**Azure Table Storage**输入，将表名更改为`friends`，然后点击**保存**。

1.  对名为`addfriend`的第二个函数重复这些步骤，但将**Azure Table Storage**设置为输出而不是输入。

接下来，让我们使用以下 C#代码实现`friends` Azure Function：

```kt
#r "Microsoft.WindowsAzure.Storage" 

using System.Net; 
using Microsoft.WindowsAzure.Storage.Table; 

public async static Task<HttpResponseMessage> Run( 
  HttpRequestMessage req, IQueryable<TableEntity> inputTable, 
  TraceWriter log) 
{ 
    dynamic data = await req.Content.ReadAsAsync<object>(); 
    string userName = data?.userName; 
    if (string.IsNullOrEmpty(userName)) 
    { 
      return new HttpResponseMessage(HttpStatusCode.BadRequest); 
    } 

    var results = inputTable 
      .Where(r => r.PartitionKey == userName) 
      .Select(r => new { Name = r.RowKey }) 
      .ToList(); 
    return req.CreateResponse(HttpStatusCode.OK, results); 
} 

```

这比我们的`login`函数简单一些。Azure Functions 可以选择使用不同于我们之前使用的`CloudTable`的不同类型的参数。当使用`IQueryable`时，我们只需编写 LINQ 表达式即可提取此函数所需的数据：指定用户的 friend 列表。我们计划将用户的名字作为`PartitionKey`，朋友的名字作为`RowKey`。然后我们只需在 HTTP 响应中返回这些值。

现在，让我们使用以下 C#代码实现`addfriend`函数：

```kt
#r "Microsoft.WindowsAzure.Storage" 

using System.Net; 
using Microsoft.WindowsAzure.Storage.Table; 

public async static Task<HttpResponseMessage> Run( 
  HttpRequestMessage req, CloudTable outputTable, TraceWriter log) 
{ 
  dynamic data = await req.Content.ReadAsAsync<object>(); 
  string userName = data?.userName; 
  string friendName = data?.friendName; 
  if (string.IsNullOrEmpty(userName) || 
    string.IsNullOrEmpty(friendName)) 
  { 
    return new HttpResponseMessage(HttpStatusCode.BadRequest); 
  } 

  var operation = TableOperation.InsertOrReplace(new TableEntity 
  { 
    PartitionKey = userName, 
    RowKey = friendName, 
  }); 
  var result = outputTable.Execute(operation); 

  return req.CreateResponse( 
    (HttpStatusCode)result.HttpStatusCode); 
} 

```

就像之前使用`login`函数一样，我们使用`CloudTable`向 Azure Storage Table 添加一行。同样，我们处理空白输入的可能性，并返回 Azure Storage SDK 返回的相同状态码。

最后，让我们修改`AzureWebService.cs`：

```kt
public Task<User[]> GetFriends(string userName) 
{ 
  return Post<User[]>("friends", "key_here", new 
  { 
    userName 
  }); 
}
public async Task<User> AddFriend( 
  string userName, string friendName) 
{ 
  await Post("addfriend", "key_here", new 
  { 
    userName, 
    friendName 
  }); 

  return new User 
  { 
    Name = friendName 
  }; 
} 

```

我们调用本章前面创建的帮助方法，以便轻松处理 HTTP 输入和输出到我们的 Azure Functions。确保为每个 Azure Function 使用正确的密钥。您可能需要使用工具向`friends` Azure Storage 表插入或填充一些测试数据，以便我们的 Azure Function 可以处理。

最后，我们需要创建三个更多的 Azure Functions 来处理对话和消息。返回 Azure 门户，并执行以下步骤：

1.  点击**新建函数**按钮。

1.  选择**Empty - C#**模板。

1.  输入`conversations`作为函数名称。

1.  点击**创建**按钮。

1.  点击**集成**部分。

1.  添加一个带有默认设置的**HTTP**触发器和输出，然后点击**保存**。

1.  添加一个**Azure Table Storage**输入，将表名更改为`friends`，然后点击**保存**。

1.  对名为`messages`的第二个函数重复这些步骤，表名为`messages`。

1.  对名为`sendmessage`的第三个函数重复这些步骤，但将**Azure Table Storage**设置为输出而不是输入。

`conversations`函数的 C#代码如下：

```kt
#r "Microsoft.WindowsAzure.Storage" 

using System.Net; 
using Microsoft.WindowsAzure.Storage.Table; 

public async static Task<HttpResponseMessage> Run( 
  HttpRequestMessage req, IQueryable<Conversation> inputTable, 
  TraceWriter log) 
{ 
  dynamic data = await req.Content.ReadAsAsync<object>(); 
  string userName = data?.userName; 
  if (string.IsNullOrEmpty(userName)) 
  { 
    return new HttpResponseMessage(HttpStatusCode.BadRequest); 
  } 

  var results = inputTable 
    .Where(r => r.PartitionKey == userName) 
    .Select(r => new { Id = r.RowKey, UserName = r.UserName }) 
    .ToList(); 
  return req.CreateResponse(HttpStatusCode.OK, results); 
} 

public class Conversation : TableEntity 
{ 
  public string UserName { get; set; } 
} 

```

这段代码几乎与我们之前编写的`friends`函数相同。但是，我们需要定义一个`Conversation`类，以便在表中对默认的`RowKey`和`PartitionKey`之外添加一个额外的列。

接下来，让我们为`messages`函数添加以下 C#代码：

```kt
#r "Microsoft.WindowsAzure.Storage" 

using System.Net; 
using Microsoft.WindowsAzure.Storage.Table; 

public async static Task<HttpResponseMessage> Run( 
  HttpRequestMessage req, IQueryable<Message> inputTable, 
  TraceWriter log) 
{ 
  dynamic data = await req.Content.ReadAsAsync<object>(); 
  string conversation = data?.conversation; 
  if (string.IsNullOrEmpty(conversation)) 
  { 
    return new HttpResponseMessage(HttpStatusCode.BadRequest); 
  } 

  var results = inputTable 
    .Where(r => r.PartitionKey == conversation) 
    .Select(r => new { Id = r.RowKey,  
      UserName = r.UserName, Text = r.Text }) 
    .ToList(); 
  return req.CreateResponse(HttpStatusCode.OK, results); 
} 

public class Message : TableEntity 
{ 
  public string UserName { get; set; } 
  public string Text { get; set; } 
} 

```

同样，对于我们为`friends`和`conversations`函数所做的，这应该非常直观。

最后，让我们按照以下方式为`sendmessage`函数添加以下代码：

```kt
#r "Microsoft.WindowsAzure.Storage" 

using System.Net; 
using Microsoft.WindowsAzure.Storage.Table; 

public async static Task<HttpResponseMessage> Run( 
  HttpRequestMessage req, CloudTable outputTable, TraceWriter log) 
{ 
  dynamic data = await req.Content.ReadAsAsync<object>(); 
  if (data == null) 
    return req.CreateResponse(HttpStatusCode.BadRequest); 

  var operation = TableOperation.InsertOrReplace(new Message 
  { 
    PartitionKey = data.Conversation, 
    RowKey = data.Id, 
    UserName = data.UserName, 
    Text = data.Text, 
  }); 
  var result = outputTable.Execute(operation); 

  return req.CreateResponse( 
    (HttpStatusCode)result.HttpStatusCode); 
} 

public class Message : TableEntity 
{ 
    public string UserName { get; set; } 
    public string Text { get; set; } 
} 

```

这个函数与我们处理`addfriend`的方式非常相似。在本章后面，我们将在该函数中发送推送通知。

在继续之前，让我们实现`IWebService`接口的其余部分。可以按照以下方式完成：

```kt
public Task<Conversation[]> GetConversations(string userName) 
{ 
  return Post<Conversation[]>("conversations", "key_here", new 
  { 
    userName 
  }); 
} 

public Task<Message[]> GetMessages(string conversation) 
{ 
  return Post<Message[]>("messages", "key_here", new 
  { 
    conversation 
  }); 
} 

public async Task<Message> SendMessage(Message message) 
{ 
  message.Id = Guid.NewGuid().ToString("N"); 
  await Post("sendmessage", "key_here", message); 
  return message; 
} 

```

我们客户端代码中的每个方法都非常简单，与我们调用其他 Azure 函数时所做的类似。`SendMessage`是我们唯一需要新做的一件事：为新的消息生成一个唯一的消息 ID。

这完成了我们`IWebService`的实现。如果你在此时运行应用程序，它将和之前一样运行，区别在于实际上应用程序正在与真实的网络服务器通信。新消息将保存在 Azure 存储表中，我们的 Azure 函数将处理所需的定制逻辑。请随意尝试我们的实现；你可能会发现一些 Azure 函数功能，它们与你的应用程序非常契合。

在这一点上，另一个好的练习是在我们的 Android 应用程序中设置`AzureWebService`。你应该能够在你的`Application`类中的`ServiceContainer.Register`调用进行替换。所有功能将完全与 iOS 相同。跨平台开发不是很好吗？

# 使用苹果推送通知服务

在 Azure 的角度来看，使用 Azure 通知中心在 iOS 上实现推送通知非常简单。最复杂的部分是完成苹果公司创建证书和配置文件的过程，以便配置你的 iOS 应用程序。在继续之前，请确保你有一个有效的 iOS 开发者计划账户，因为没有它你将无法发送推送通知。如果你不熟悉推送通知的概念，请查看苹果的文档，链接为[`tinyurl.com/XamarinAPNS`](http://tinyurl.com/XamarinAPNS)。

要发送推送通知，你需要设置以下内容：

+   已注册的显式 App ID 与苹果

+   针对该 App ID 的一个配置文件

+   用于触发推送通知的服务器证书

苹果提供了开发和生产两种证书，你可以使用它们从你的服务器发送推送通知。

## 设置你的配置文件

让我们从[`developer.apple.com/account`](http://developer.apple.com/account)开始，执行以下步骤：

1.  点击**标识符**链接。

1.  点击窗口右上角的加号按钮。

1.  为捆绑 ID 输入描述，例如`XamSnap`。

1.  在**显式 App ID**部分输入你的捆绑 ID。这应该与你`Info.plist`文件中设置的捆绑 ID 相匹配，例如，`com.yourcompanyname.xamsnap`。

1.  在**应用服务**下，确保勾选了**推送通知**。

1.  现在，点击**继续**。

1.  审核你的最终设置，然后点击**提交**。

这将创建一个显式 App ID，类似于我们可以在以下屏幕截图中看到的 ID，我们可以使用它来发送推送通知：

![设置你的配置文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00252.jpeg)

对于推送通知，我们必须使用一个显式 App ID 的配置文件，这不是一个开发证书。现在让我们设置一个配置文件：

1.  点击右侧**供应配置文件**下的**开发**链接。

1.  点击右上角的加号按钮。

1.  勾选**iOS 应用开发**并点击**继续**。

1.  选择我们刚刚创建的应用 ID 并点击**继续**。

1.  选择开发者并点击**继续**。

1.  选择你将要使用的设备并点击**继续**。

1.  为配置文件输入一个名称并点击**生成**。

1.  下载配置文件并安装，或者在**XCode**的**偏好设置** | **账户**中使用同步按钮。

完成后，你应该会看到一个如下所示的成功的网页：

![设置你的供应配置文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00253.jpeg)

## 设置推送通知的证书

接下来，我们执行以下步骤来设置服务器需要的证书：

1.  点击右侧**证书**下的**开发**链接。

1.  点击右上角的加号按钮。

1.  启用**苹果推送通知服务 SSL（沙盒）**并点击**继续**。

1.  像之前一样选择你的应用 ID 并点击**继续**。

1.  按照苹果的说明创建一个新的证书签名请求。你也可以参考第七章，*在设备上部署和测试*，或者找到之前的`*.certSigningRequest`文件。

1.  然后，点击**继续**。

1.  上传签名请求文件并点击**生成**。

1.  接下来，点击**下载**。

1.  打开文件，将证书导入**钥匙串**。

1.  在**钥匙串**中找到证书。它将被命名为**Apple Development iOS Push Services**，并包含你的捆绑 ID。

1.  右键点击证书并将其导出到你的文件系统的某个位置。输入一个你能记住的密码。

这将创建我们需要从 Azure 通知中心向用户发送推送通知的证书。

返回 Azure 门户，执行以下步骤创建 Azure 通知中心：

1.  导航到存放你的**Azure Function App**的资源组。

1.  点击加号按钮，向资源组添加新服务。

1.  选择一个**通知中心名称**和**命名空间**，例如`xamsnap`。

1.  确保选择了所需的数据中心和资源组并点击**创建**。

剩下的工作就是回到 Azure 门户，从你的 Azure 通知中心上传证书。你可以在**通知服务** | **苹果(APNS)** | **上传证书**中找到这个设置，如下截图所示：

![为推送通知设置证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00254.jpeg)

这个上传完成了我们需要从苹果方面进行的配置。

## 为推送通知进行客户端侧的更改

接下来，让我们回到 Xamarin Studio 中的`XamSnap.iOS`项目，进行客户端必要的推送通知更改。我们首先需要在共享代码中添加几个新的类。

在我们的 XamSnap PCL 项目中，创建一个名为`INotificationService`的新接口，如下所示：

```kt
public interface INotificationService 
{ 
  void Start(string userName); 
  void SetToken(object deviceToken); 
} 

```

接下来，我们需要在登录完成后调用`Start`。在`LoginViewModel.cs`中，在成功登录后添加以下几行：

```kt
//At the top of the class 
readonly INotificationService notificationService =  
  ServiceContainer.Resolve<INotificationService>();

//Later, after a successful login 
notificationService.Start(UserName); 

```

接下来，让我们在 iOS 项目中的一个名为`AppleNotificationService`的新类中实现这个接口，如下所示：

```kt
public class AppleNotificationService : INotificationService 
{ 
  private readonly CultureInfo enUS =  
    CultureInfo.CreateSpecificCulture("en-US"); 
  private SBNotificationHub hub; 
  private string userName; 
} 

```

我们需要定义一个`CultureInfo`对象供稍后使用，还需要两个私有变量，分别用于我们的通知中心和当前登录的用户名。

现在，让我们实现`Start`方法：

```kt
public void Start(string userName) 
{ 
  this.userName = userName; 

  var pushSettings =  
    UIUserNotificationSettings.GetSettingsForTypes( 
    UIUserNotificationType.Alert |  
    UIUserNotificationType.Badge |  
    UIUserNotificationType.Sound, null); 

  UIApplication.SharedApplication 
    .RegisterUserNotificationSettings(pushSettings); 
} 

```

我们将用户名存储在成员变量中，然后调用原生 iOS API 来为远程通知设置注册。

接下来，我们需要如下实现`SetToken`方法：

```kt
public void SetToken(object deviceToken) 
{ 
    if (hub == null) 
    { 
        hub = new SBNotificationHub("yourconnection", "xamsnap"); 
    } 

    string template = "{"aps": {"alert": "$(message)"}}"; 
    var tags = new NSSet(userName); 
    hub.RegisterTemplateAsync((NSData)deviceToken, "iOS",  
      template, DateTime.Now.AddDays(90).ToString(enUS), tags, 
      errorCallback => 
      { 
        if (errorCallback != null) 
          Console.WriteLine("Push Error: " + errorCallback); 
      }); 
}} 

```

首先，如有需要，我们创建了一个新的通知中心。确保将`yourconnection`替换为只有**监听**权限的真实连接字符串。这可以在 Azure 门户的**设置** | **访问策略** | **DefaultListenSharedAccessSignature**中找到。接下来，我们声明了一个 iOS 模板，它使用`message`变量以 iOS 推送通知的正确格式。这是通知中心的一个特性，支持跨平台推送通知。最后，我们将设备令牌与通知中心注册，并记录可能发生的任何错误。

接下来，我们需要对`AppDelegate.cs`进行一些 iOS 特定的更改：

```kt
public override void DidRegisterUserNotificationSettings( 
  UIApplication application,  
  UIUserNotificationSettings notificationSettings) 
{ 
  application.RegisterForRemoteNotifications(); 
} 

public override void RegisteredForRemoteNotifications( 
  UIApplication application, NSData deviceToken) 
{ 
  var notificationService =  
    ServiceContainer.Resolve<INotificationService>(); 
  notificationService.SetToken(deviceToken); 
} 

public override void FailedToRegisterForRemoteNotifications( 
  UIApplication application, NSError error) 
{ 
  Console.WriteLine("Push Error: " + error.LocalizedDescription); 
} 

```

在前面的代码片段中，我们实现了一些重要方法。`DidRegisterUserNotificationSettings`是用户接受 iOS 权限弹窗时的回调。`RegisteredForRemoteNotifications`将在 Apple 成功从其服务器返回设备令牌时发生。我们将设备令牌通过`INotificationService`传递给 Azure 通知中心。我们还实现了`FailedToRegisterForRemoteNotifications`，以报告整个过程中可能发生的任何错误。

最后，我们需要添加一个小修改来注册我们的`INotificationService`实现：

```kt
ServiceContainer.Register<INotificationService>( 
  () => new AppleNotificationService()); 

```

## 从服务器端发送推送通知

由于我们已经成功为 iOS 配置了推送通知，现在是从我们的`sendmessage` Azure Function 实际发送它们的时候了。Azure Functions 开箱即支持通知中心，但在撰写本文时，无法将它们作为输出使用，并指定针对特定用户的标签。幸运的是，Azure Functions 只是 C#代码，因此我们可以轻松利用 Azure 通知中心 SDK 从代码手动发送推送通知。让我们切换到 Azure 门户，并在服务器端进行剩余的更改。

首先，让我们在顶部添加几条语句以包含 Azure 通知中心 SDK：

```kt
#r "Microsoft.Azure.NotificationHubs"  
using Microsoft.Azure.NotificationHubs; 

```

接下来，让我们添加一个快速发送推送通知的方法：

```kt
private async static Task SendPush( 
  string userName, string message) 
{ 
  var dictionary = new Dictionary<string, string>(); 
  dictionary["message"] = userName + ": " + message; 

  var hub = NotificationHubClient 
    .CreateClientFromConnectionString("yourconnection "xamsnap"); 
  await hub.SendTemplateNotificationAsync(dictionary, userName); 
} 

```

确保将`yourconnection`替换为具有**发送**和**监听**权限的有效连接字符串。默认情况下，您可以在 Azure 门户中使用名为**DefaultFullSharedAccessSignature**的那个。

最后，我们需要在 Azure 函数被调用时实际发送推送通知：

```kt
//Place this right before returning the HTTP response 
await SendPush((string)data.UserName, (string)data.Text); 

```

要测试推送通知，请部署应用程序并使用辅助用户登录。登录后，你可以使用主页按钮将应用程序后台运行。接下来，在你的 iOS 模拟器上以主要用户身份登录并发送消息。你应该会收到推送通知，如下面的截图所示：

![从服务器端发送推送通知](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00255.jpeg)

### 提示

如果你遇到一些问题，尝试从 Azure 门户下的通知中心发送测试通知，然后点击**故障排除** | **测试发送**。你可以使用本章中使用的原生格式或自定义模板格式发送测试通知。

# 实现 Google Cloud Messaging

由于我们已经在前面的共享代码和 Azure 上设置好了所需的一切，此时为 Android 设置推送通知将少很多工作。继续操作，你需要一个带有验证电子邮件地址的 Google 帐户；不过，如果你有的话，我建议使用在**Google Play**注册的账户。你可以参考关于 **Google Cloud Messaging** (**GCM**) 的完整文档，地址是 [`developers.google.com/cloud-messaging/`](https://developers.google.com/cloud-messaging/)。

### 提示

请注意，Google Cloud Messaging 需要 Android 设备上安装了 Google APIs，并且 Android 操作系统至少是版本 2.2。

首先，访问 [`cloud.google.com/console`](http://cloud.google.com/console)，然后执行以下步骤：

1.  点击**创建项目**按钮。

1.  输入一个适当的项目名称，如`XamSnap`。

1.  同意**服务条款**。

1.  点击**创建**按钮。

1.  在创建你的第一个项目时，你可能需要验证与你的账户关联的手机号码。

1.  注意**概述**页面上的**项目编号**字段。我们稍后需要这个数字。

下面的截图展示了我们的项目小部件在**仪表盘**标签上的样子：

![实现 Google Cloud Messaging](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00256.jpeg)

现在，我们可以按照以下步骤继续我们的设置：

1.  点击**使用 Google APIs**小部件。

1.  点击**库**，搜索**Google Cloud Messaging for Android**。

1.  点击顶部的**启用**按钮以启用服务。你可能需要接受另一个协议。

1.  点击顶部警告提示中出现的**前往凭据**。

1.  点击**我需要哪些凭据？**按钮。

1.  点击**限制密钥**，选择**IP 地址**，并输入**0.0.0.0/0**。

1.  复制密钥到剪贴板以备后用，并点击**保存**。

1.  切换到 Azure 门户，导航到你的 Azure 通知中心实例中的**通知服务** | **Google (GCM)**部分。

1.  在**API 密钥**字段中粘贴 API 密钥，并点击**保存**。请注意，第一次，Google 控制台可能需要长达五分钟的时间密钥才能生效。

这就完成了我们在 Azure 方面的设置。我们需要为 Xamarin.Android 应用获取几个开源库。首先，从 NuGet 安装 **Xamarin.Azure.NotificationHubs.Android**，然后从 Xamarin 组件商店安装 **Google Cloud Messaging Client**。

接下来，创建一个名为 `Constants.cs` 的新类，如下所示：

```kt
public static class Constants 
{ 
    public const string ProjectId = "yourprojectid"; 
    public const string ConnectionString = "yourconnectionstring"; 
    public const string HubName = "xamsnap"; 
} 

```

使用之前在 Google 云控制台 **概览** 页面找到的项目编号填写 `ProjectId` 值。`ConnectionString` 和 `HubName` 应该与为 iOS 输入的内容完全相同。

接下来，我们需要设置一些权限以支持我们应用中的推送通知。在这个文件中的命名空间声明之上，添加以下内容：

```kt
[assembly: Permission(Name =  
  "@PACKAGE_NAME@.permission.C2D_MESSAGE")] 
[assembly: UsesPermission(Name =  
  "@PACKAGE_NAME@.permission.C2D_MESSAGE")] 
[assembly: UsesPermission(Name =  
  "com.google.android.c2dm.permission.RECEIVE")] 
[assembly: UsesPermission( 
  Name = "android.permission.GET_ACCOUNTS")] 
[assembly: UsesPermission( 
  Name = "android.permission.WAKE_LOCK")] 

```

你也可以在我们的 `AndroidManifest.xml` 文件中进行这些更改；然而，使用 C# 属性可能更好，因为它在输入时提供了代码补全的能力。

接下来，创建另一个名为 `PushBroadcastReceiver.cs` 的新类，如下所示：

```kt
[BroadcastReceiver(Permission =  
  Gcm.Client.Constants.PERMISSION_GCM_INTENTS)] 
[IntentFilter(new string[] {  
  Gcm.Client.Constants.INTENT_FROM_GCM_MESSAGE },  
  Categories = new string[] { "@PACKAGE_NAME@" })] 
[IntentFilter(new string[] {  
  Gcm.Client.Constants.INTENT_FROM_GCM_REGISTRATION_CALLBACK },  
  Categories = new string[] { "@PACKAGE_NAME@" })] 
[IntentFilter(new string[] {  
  Gcm.Client.Constants.INTENT_FROM_GCM_LIBRARY_RETRY },  
  Categories = new string[] { "@PACKAGE_NAME@" })] 
public class PushBroadcastReceiver :  
  GcmBroadcastReceiverBase<PushHandlerService> 
{ } 

```

`PushBroadcastReceiver.cs` 类设置了 `BroadcastReceiver`，这是安卓应用之间通信的原生方式。关于这个主题的更多信息，请查看安卓文档中的相关内容：[`developer.android.com/reference/android/content/BroadcastReceiver.html.`](http://developer.android.com/reference/android/content/BroadcastReceiver.html)

接下来，创建最后一个名为 `PushHandlerService.cs` 的类，如下所示：

```kt
[Service] 
public class PushHandlerService : GcmServiceBase  
{ 
  public PushHandlerService() : base (PushConstants.ProjectNumber)  
  { } 
} 

```

现在，右键点击 `GcmServiceBase` 并选择 **重构** | **实现抽象成员**。接下来，让我们逐个实现每个成员：

```kt
protected async override void OnRegistered( 
  Context context, string registrationId) 
{     
  var notificationService =  
    ServiceContainer.Resolve<INotificationService>(); 
  notificationService.SetToken(registrationId); 
} 

```

上述代码与我们之前在 iOS 上的操作非常相似。我们只需将 `registrationId` 值发送给 `INotificationService`。

接下来，当接收到消息时，我们需要编写以下代码：

```kt
protected override void OnMessage( 
  Context context, Intent intent) 
{ 
  string message = intent.Extras.GetString("message"); 
  if (!string.IsNullOrEmpty(message)) 
  { 
    var notificationManager = (NotificationManager) 
      GetSystemService(Context.NotificationService); 

    var notification = new NotificationCompat.Builder(this) 
      .SetContentIntent( 
        PendingIntent.GetActivity(this, 0,  
          new Intent(this, typeof(LoginActivity)), 0)) 
      .SetSmallIcon(Android.Resource.Drawable.SymActionEmail) 
      .SetAutoCancel(true) 
      .SetContentTitle("XamSnap") 
      .SetContentText(message) 
      .Build(); 
    notificationManager.Notify(1, notification); 
  } 
} 

```

这段代码实际上会从通知中提取值，并在安卓设备的消息中心显示它们。我们使用了内置资源 `SymActionEmail` 来在通知中显示一个电子邮件图标。

然后，我们只需要实现两个更多的抽象方法。现在，我们只需使用 `Console.WriteLine` 来报告这些事件，如下所示：

```kt
protected override void OnUnRegistered( 
  Context context, string registrationId) 
{ 
  Console.WriteLine("GCM unregistered!"); 
} 

protected override void OnError ( 
  Context context, string errorId) 
{ 
  Console.WriteLine("GCM error: " + errorId); 
} 

```

在未来的开发中，你应该考虑在调用 `OnUnRegistered` 时从 Azure 移除注册。有时，用户的 `registrationId` 会发生变化，因此这里是应用程序得到通知的地方。

接下来，我们需要为安卓实现 `INotificationService`。首先创建一个名为 `GoogleNotificationService.cs` 的新文件，并添加以下代码：

```kt
public class GoogleNotificationService : INotificationService 
{ 
  readonly Context context; 
  NotificationHub hub; 
  string userName; 

  public GoogleNotificationService(Context context) 
  { 
    this.context = context; 
  } 

  public void SetToken(object deviceToken) 
  { 
    hub = new NotificationHub( 
      Constants.HubName, Constants.ConnectionString, context); 
    try 
    { 
      string template = "{"data":{"message":"$(message)"}}"; 
      hub.RegisterTemplate((string)deviceToken,  
        "Android", template, userName); 
    } 
    catch (Exception exc) 
    { 
      Console.WriteLine("RegisterTemplate Error: " + exc.Message); 
    } 
  } 

  public void Start(string userName) 
  { 
    this.userName = userName; 
    GcmClient.CheckDevice(context); 
    GcmClient.CheckManifest(context); 
    GcmClient.Register(context, Constants.ProjectId); 
  } 
} 

```

接下来，打开 `Application.cs` 并添加以下行来注册我们的新服务：

```kt
ServiceContainer.Register<INotificationService>( 
  () => new GoogleNotificationService(this)); 

```

现在，如果你重复在 iOS 上测试推送通知的步骤，你应该能够向我们的安卓应用发送一个推送通知。甚至更好，你应该能够跨平台发送推送通知，因为 iOS 用户可以向安卓用户发送消息：

![实现 Google 云消息传递](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00257.jpeg)

# 总结

在本章中，我们了解了 Windows Azure 提供的服务：基础设施即服务和平台即服务。我们注册了一个免费的 Windows Azure 账户并设置了一个 Azure Function App 实例。我们实现了客户端代码，以便针对我们的 Azure Functions 发起请求。最后，我们使用 Azure 通知中心为 iOS 实现了推送通知，以通过 Apple 推送通知服务和 Google 云消息将消息集中发送到 iOS 和 Android 设备。

使用 Azure Functions，我们可以在不编写太多服务器端代码的情况下完成任务。在下一章中，我们将探讨如何使用 Xamarin 使用第三方库。这包括从 Xamarin 组件商店到使用本地 Objective-C 或 Java 库的所有内容。


# 第十章：第三方库

Xamarin 支持.NET 框架的一个子集，但大部分包括了您在.NET 基类库中期望的所有标准 API。因此，大量的 C#开源库可以直接在 Xamarin 项目中使用。此外，如果一个开源项目没有 Xamarin 或可移植类库版本，将代码移植到 Xamarin 项目中通常非常直接。Xamarin 还支持调用原生 Objective-C 和 Java 库，因此我们将探索这些作为重用现有代码的额外手段。

在本章中，我们将涵盖以下内容：

+   Xamarin 组件商店

+   移植现有的 C#库

+   Objective-C 绑定

+   Java 绑定

# Xamarin 组件商店

向项目中添加第三方组件的主要且明显的方式是通过 Xamarin 组件商店。组件商店与所有 C#开发者都熟悉的*NuGet 包管理器*非常相似，不同之处在于组件商店还包含不免费的付费组件。所有 Xamarin 组件还必须包含完整的示例项目和入门指南，而 NuGet 在其包中并不固有地提供文档。

所有`Xamarin.iOS`和`Xamarin.Android`项目都带有一个`Components`文件夹。要开始使用，只需右键点击该文件夹，选择**获取更多组件**来启动商店对话框，如下面的截图所示：

![Xamarin 组件商店](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00258.jpeg)

在撰写本书时，有超过 200 个组件可用于增强您的 iOS 和 Android 应用程序。这是寻找 Xamarin 应用程序中最常见组件的好地方。每个组件都附有插图、可能的演示视频、评论以及其他在购买付费组件之前需要的信息。

最知名且有用的组件如下：

+   **Json.NET**：这是在 C#中解析和序列化 JSON 的事实上的标准。 

+   **RestSharp**：这是一个在.NET 中常用的简单 REST 客户端。

+   **SQLite.NET**：这是一个简单的**对象关系映射**（**ORM**）工具，用于在移动应用程序中操作本地 SQLite 数据库。

+   **Facebook SDK**：这是 Facebook 提供的标准软件开发工具包，用于将 Facebook 的服务集成到您的应用程序中。

+   **Xamarin.Mobile**：这是一个跨平台库，通过公共 API 访问设备的联系人、GPS、照片库和相机。

+   **ZXing.Net.Mobile**：流行的条形码扫描库**ZXing**（**Zebra Crossing**）的.NET 版本。

请注意，其中一些库是原生 Java 或 Objective-C 库，而有些则是纯 C#库。Xamarin 从底层开始构建，以支持调用原生库，因此组件商店提供了许多 Objective-C 或 Java 开发者在开发移动应用程序时会使用的常见库。

你也可以将你自己的组件提交到组件商店。如果你有一个有用的开源项目，或者只是想赚点外快，创建一个组件很简单。我们在这本书中不会涉及，但可以访问[`components.xamarin.com/submit`](http://components.xamarin.com/submit)了解该主题的完整文档，如下面的截图所示：

![Xamarin 组件商店](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00259.jpeg)

# 迁移现有 C#库

尽管 Xamarin 正在成为一个流行的平台，但许多开源.NET 库在支持`Xamarin.iOS`和`Xamarin.Android`方面还远远跟不上。但在这些情况下，你绝对不是没有机会。通常，如果库有 Silverlight 或 Windows Phone 版本，你可以简单创建一个 iOS 或 Android 类库，并添加文件，无需更改代码。

为了说明这个过程，让我们迁移一个没有 Xamarin 或可移植类库支持的的开源项目。我选择了一个名为**Ninject**的依赖注入库，因为它的实用性和与忍者的关联。更多关于该库的信息可以在[`www.ninject.org/`](http://www.ninject.org/)找到。

让我们开始设置库以与 Xamarin 项目一起工作，如下所示：

1.  首先，从[`github.com/ninject/ninject`](https://github.com/ninject/ninject)下载 Ninject 的源代码。

1.  创建一个名为`Ninject.iOS`的新的解决方案，其中包含一个**iOS 类库**项目。

1.  将`Ninject`主项目中的所有文件链接进来。确保使用**添加现有文件夹**对话框以加快此过程。

### 提示

如果你不太熟悉 GitHub，我建议下载 GitHub 桌面客户端，这是一个适用于 Windows 或 OS X 的优质客户端应用，可在[`desktop.github.com/`](https://desktop.github.com/)找到。

现在，尝试编译`Ninject.iOS`项目；你会在一个名为`DynamicMethodFactory.cs`的文件中遇到几个编译错误，如下面的截图所示：

![迁移现有 C#库](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00260.jpeg)

打开`DynamicMethodInjectorFactory.cs`文件，并注意文件顶部以下代码：

```kt
#if !NO_LCG 
namespace Ninject.Injection 
{ 
    using System; 
    using System.Reflection; 
    using System.Reflection.Emit; 
    using Ninject.Components; 

/// *** File contents here *** 

#endif 

```

由于苹果平台的限制，在 iOS 上无法使用`System.Reflection.Emit`。幸运的是，库作者创建了一个名为`NO_LCG`（代表**轻量级代码生成**）的预处理器指令，以允许库在不支持`System.Reflection.Emit`的平台运行。

为了修复我们的 iOS 项目，请按照以下步骤操作：

1.  打开项目选项，导航到**构建** | **编译器**部分。

1.  在**配置**下拉菜单中，为**调试**和**发布**的**定义符号**字段添加`NO_LCG`。

1.  点击**确定**以保存你的更改。

如果你现在编译项目，它将成功完成，并创建一个`Ninject.iOS.dll`文件，你可以从任何`Xamarin.iOS`项目中引用它。你也可以直接引用`Ninject.iOS`项目，而不是使用`*.dll`文件。

在这一点上，你可能希望重复该过程以创建一个`Xamarin.Android`类库项目。幸运的是，`Xamarin.Android`支持`System.Reflection.Emit`，所以如果你愿意，可以跳过添加额外的预处理器指令。

# Objective-C 绑定

Xamarin 开发了一个复杂的系统，用于在 iOS 项目中从 C#调用本地 Objective-C 库。`Xamarin.iOS`的核心使用相同的技术来调用**UIKit**、**CoreGraphics**和其他 iOS 框架中的本地 Apple API。开发者可以使用简单的接口和属性创建 iOS 绑定项目，将 Objective-C 类和方法暴露给 C#。

为了帮助创建 Objective-C 绑定，Xamarin 创建了一个名为**Objective Sharpie**的小工具，它可以处理 Objective-C 头文件并导出有效的 C#定义，以便添加到绑定项目中。这个工具是大多数绑定的良好起点，在大多数情况下，它可以让你的绑定项目完成大约 75%的工作。大多数时候，你可能想要手动编辑并精细调整，使其更友好地适应 C#。

### 提示

请注意，iOS 绑定项目可以在 Visual Studio 中创建；然而，Objective Sharpie 是一个 OS X 的命令行工具。它利用了 Xcode 中包含的工具，因此 iOS 绑定开发最好在 Mac OS X 上完成。

作为示例，我们将为 iOS 编写 Google Analytics 库的绑定。这是一个简单且有用的库，可以跟踪你的 iOS 或 Android 应用程序中的用户活动。在编写时，Google Analytics SDK 的版本是 3.17，因此随着新版本的发布，这些说明可能会发生变化。

从[`developer.xamarin.com/guides/cross-platform/macios/binding/objective-sharpie/`](https://developer.xamarin.com/guides/cross-platform/macios/binding/objective-sharpie/)下载并安装 Objective Sharpie，并执行以下步骤：

1.  从[`tinyurl.com/GoogleAnalyticsForiOS`](https://tinyurl.com/GoogleAnalyticsForiOS)下载最新的 iOS Google Analytics SDK。

1.  创建一个新的**iOS** | **绑定库**项目，名为`GoogleAnalytics.iOS`。

1.  从第一步中提取 zip 文件的内容，并将`GoogleAnalytics`文件夹移动到与绑定项目相同的目录中。

1.  打开**终端**并导航到新项目的同一目录。

1.  使用以下命令运行**Objective Sharpie**：

```kt
        sharpie bind --output=. --namespace=GoogleAnalytics.iOS 
          --sdk=iphoneos10.0 ./GoogleAnalytics/Library/*.h 
        mv -f ApiDefinitions.cs ApiDefinition.cs 
        mv -f StructsAndEnums.cs Structs.cs 

```

Objective Sharpie 将输出两个文件：`ApiDefinitions.cs`和`Structs.cs`。接下来的两个命令将把文件复制到由**绑定库**项目模板创建的默认文件之上。

### 提示

请注意，在编写此命令时，使用了 iOS 10 SDK。要发现你需要为`--sdk`选项输入什么，请运行`sharpie xcode --sdks`，你将在输出中看到打印出的值。

现在，回到你的绑定项目，你会注意到 Objective Sharpie 已经为库中头文件中发现的每个类生成了一个接口定义。它还生成了库使用的许多 `enum` 值，并在可能的情况下更改大小写和命名约定以更接近 C#。

在阅读绑定内容时，你会注意到几个 C# 属性，它们定义了关于 Objective-C 库的不同方面，例如以下内容：

+   `BaseType`：这会将接口声明为一个 Objective-C 类。基类（也称为超类）会传递给属性。如果没有基类，应使用 `NSObject`。

+   `Export`：这会在 Objective-C 类上声明一个方法或属性。传递一个将 Objective-C 名称映射到 C# 名称的字符串。Objective-C 方法名通常如下形式：`myMethod:someParam:someOtherParam`。

+   `Static`：这会将方法或属性标记为 C# 中的 `static`。

+   `Bind`：用于属性上，将 getter 或 setter 映射到不同的 Objective-C 方法。Objective-C 属性可以为属性的 getter 或 setter 重命名。

+   `NullAllowed`：这允许将 `null` 传递给方法或属性。默认情况下，如果发生这种情况，将抛出异常。

+   `Field`：这会声明一个 Objective-C 字段，在 C# 中作为公共变量暴露。

+   `Model`：这标识了一个类到 `Xamarin.iOS`，其方法可以选择性地被重写。这通常用于 Objective-C 委托。

+   `Internal`：这用 C# 内部关键字标记生成的成员。它可以用来隐藏那些你不想暴露给外部世界的特定成员。

+   `Abstract`：这标识了一个 Objective-C 方法为必需的，与 `Model` 密切相关。在 C# 中，它将生成一个抽象方法。

需要知道的唯一其他规则是如何定义构造函数。由于 C# 接口不支持构造函数，Xamarin 必须为此发明一个约定。

要定义除了默认构造函数之外的构造函数，请使用以下代码：

```kt
[Export("initWithFrame:")] 
IntPtr Constructor(RectangleF frame); 

```

这将在类上定义一个构造函数，该构造函数以 `RectangleF` 作为参数。方法名 `Constructor` 和返回类型 `IntPtr` 会让 Xamarin 编译器生成一个构造函数。

现在，让我们回到我们的绑定项目以完成所有设置。如果在这一点上编译项目，你会得到几个编译错误。让我们逐一修复它们，如下所示：

1.  将 Google Analytics 下载中的 `libGoogleAnalyticsServices.a` 和 `libAdIdAccess.a` 添加为**本地引用**。

1.  更改 `Structs.cs` 中找到的枚举 `GAILogLevel` 和 `GAIDispatchResult` 的基类型为 `ulong`。

1.  从 `ApiDefinitions.cs` 中找到的 `Constants` 类中移除 `[Static]` 的重复声明。

1.  移除所有的 `Verify` 属性。这些是 Objective Sharpie 对其执行的操作不确定的地方。在我们的示例中，它们都是好的，所以安全地移除它们。

在这一点上，如果你尝试在 iOS 项目中使用该库，你会得到如下错误：

```kt
Error MT5210: Native linking failed, undefined symbol:
 _FooBar. Please verify that all the necessary frameworks
 have been referenced and native libraries are properly
 linked in.

```

我们需要定义 Objective-C 库使用的其他框架和库。这类似于 C#中引用的工作方式。如果我们查看 Google Analytics 文档，它会告诉你必须添加`CoreData`、`SystemConfiguration`和`libsqlite3.dylib`。

右键点击到`libGoogleAnalyticsServices`的本地引用，选择**属性**，并进行以下更改：

1.  将`Frameworks`设置为`CoreData SystemConfiguration`。

1.  将`Linker Flags`设置为`-lsqlite3`。

原生 Objective-C 库通过以下选项之一引用其他库：

+   **框架**：将它们添加到`LinkWith`属性的`Frameworks`值中，用空格分隔。

+   **弱框架**：以同样的方式将它们添加到`LinkWith`属性的`WeakFrameworks`属性中。弱框架是可以忽略的库（如果找不到）。在这种情况下，iOS 6 中添加了`AdSupport`；然而，这个库仍然可以在旧版本的 iOS 上工作。

+   **动态库**：如`libz.dylib`可以在`LinkerFlags`中声明。通常，去掉`.dylib`扩展名，并将`lib`替换为`-l`。

实施这些更改后，你将能够从 iOS 项目中成功使用该库。要了解有关 Objective-C 绑定的完整文档，请访问 Xamarin 文档网站：[`developer.xamarin.com/guides/ios/`](https://developer.xamarin.com/guides/ios/)。

# Java 绑定

与 iOS 类似，Xamarin 完全支持通过`Xamarin.Android`从 C#调用 Java 库。原生 Android SDK 以这种方式工作，开发者可以利用`Android Java Bindings`项目在 C#中利用其他原生 Java 库。这里的主要区别是，与 Objective-C 绑定相比，手动操作要少得多。Java 语法与 C#非常相似，因此许多映射都是一一对应的。此外，Java 的库中包含了元数据信息，Xamarin 利用这些信息自动生成调用 Java 所需的 C#代码。

举个例子，让我们为 Google Analytics SDK 的 Android 版本创建一个绑定。在开始之前，下载 SDK：[`developers.google.com/analytics/devguides/collection/android/v3/`](https://developers.google.com/analytics/devguides/collection/android/v3/)。在撰写本文时，Google Analytics 正在迁移到 Google Play Services，但我们将使用这个 Java 库作为一个练习，用于创建供 C#使用的 Java 绑定。

让我们按照以下步骤开始创建 Java 绑定：

1.  在 Xamarin Studio 中启动一个全新的`Android | Library | Bindings Library`项目。如果你愿意，可以使用与 iOS 相同的解决方案。

1.  将项目命名为`GoogleAnalytics.Droid`。

1.  从 Android SDK 中将`libGoogleAnalyticsServices.jar`添加到项目下的`Jars`文件夹中。

1.  构建项目。你将得到一些错误，我们稍后会解决这些问题。

你在 Java 绑定上花费的大部分时间将用于修复阻止生成的 C#代码编译的小问题。但是不要担心；许多库在第一次尝试时无需进行任何更改就能正常工作。通常，Java 库越大，你需要做的工作就越多，以使其与 C#一起工作。

### 提示

请注意，如果你首次编译时没有错误，但是有许多警告，提示类似于`unsupported major.minor version 52.0`的内容，那么你需要安装较新版本的 Java JDK。从[`tinyurl.com/XamarinJDK8`](http://tinyurl.com/XamarinJDK8)下载 JDK 1.8，并在设置中指向 Xamarin Studio 或 Visual Studio 的新版本 JDK。

你可能会遇到以下问题类型：

+   **Java 混淆**：如果库通过像**ProGuard**这样的混淆工具运行，那么类和方法名称可能不是有效的 C#名称。

+   **协变返回类型**：Java 对于子类中重写方法的返回类型有不同的规则。因此，你可能需要修改生成的 C#代码的返回类型以编译通过。

+   **可见性**：Java 的访问性规则与 C#的不同；子类中方法的可见性可以改变。有时你需要在 C#中改变可见性以使其编译通过。

+   **命名冲突**：有时，C#代码生成器可能会犯一些错误，生成两个名称相同的成员或类。

+   **Java 泛型**：Java 中的泛型类常常会在 C#中引起问题。

# 在 Java 绑定中使用 XPath

因此，在我们开始解决 Java 绑定中的这些问题之前，首先让我们清理项目中的命名空间。默认情况下，Java 命名空间的形式为`com.mycompany.mylibrary`，所以让我们将定义更改为更接近 C#的形式。在项目的`Transforms`目录中，打开`Metadata.xml`，并在根元数据节点内添加以下 XML 标签：

```kt
<attr path="/api/package[@name='com.google.analytics.tracking   
  .android']" name="managedName">GoogleAnalytics.Tracking</attr> 

```

`attr`节点告诉 Xamarin 编译器需要替换 Java 定义中的什么内容，以另一个值。在这种情况下，我们将包的`managedName`替换为`GoogleAnalytics.Tracking`，因为它在 C#中更有意义。路径值可能看起来有点奇怪，这是因为它使用了名为**XPath**的 XML 匹配查询语言。一般来说，可以把它看作是 XML 的模式匹配查询。要了解 XPath 语法的完整文档，请查看网络上的一些资源，例如[`w3schools.com/xpath`](http://w3schools.com/xpath)。

在这一点上，你可能会问自己，XPath 表达式与什么匹配？回到 Xamarin Studio，在顶部的解决方案上右键点击。选择 **显示选项** | **显示所有文件**。在 `obj` 文件夹下的 `Debug` 文件夹中打开 `api.xml`。这是 Java 定义文件，描述了 Java 库中的所有类型和方法。你可能注意到这里的 XML 直接与我们即将编写的 XPath 表达式相关。

接下来的一步，让我们移除所有我们不打算在此库中使用的包（或命名空间）。对于大型库来说，这通常是个好主意，因为你不想浪费时间修复你甚至不会从 C# 调用的库部分的问题。

在 `Metadata.xml` 中添加以下声明：

```kt
<remove-node path="/api/package[@name='com.google.analytics
   .containertag.common']" /> 
<remove-node path="/api/package[@name='com.google.analytics
   .containertag.proto']" /> 
<remove-node path="/api/package[@name='com.google.analytics
   .midtier.proto.containertag']" /> 
<remove-node path="/api/package[@name='com.google.android
   .gms.analytics.internal']" /> 
<remove-node path="/api/package[@name='com.google.android
   .gms.common.util']" /> 
<remove-node 
   path="/api/package[@name='com.google.tagmanager']" /> 
<remove-node
   path="/api/package[@name='com.google.tagmanager.proto']" /> 
<remove-node
   path="/api/package[@name='com.google.tagmanager.protobuf.nano']" /> 

```

### 提示

请注意，移除这些命名空间实际上并没有从你的绑定中删除编译后的 Java 代码。它只是阻止绑定项目生成使用此命名空间中的类的 C# 代码。

现在当你构建库时，我们可以开始解决问题。你收到的第一个错误将是如下所示的内容：

```kt
GoogleAnalytics.Tracking.GoogleAnalytics.cs(74,74):
 Error CS0234: The type or namespace name `TrackerHandler'
 does not exist in the namespace `GoogleAnalytics.Tracking'.
 Are you missing an assembly reference?

```

如果我们在 `api.xml` 文件中找到 `TrackerHandler`，我们会看到以下类声明：

```kt
<class
   abstract="true" deprecated="not deprecated"
   extends="java.lang.Object"
   extends-generic-aware="java.lang.Object"
   final="false" name="TrackerHandler"
   static="false" visibility=""/> 

```

那么，你能发现问题所在吗？我们需要填写 `visibility` XML 属性，不知何故它是空的。在 `Metadata.xml` 中添加以下行：

```kt
<attr
  path="/api/package[@name='com.google.analytics
  .tracking.android']/class[@name='TrackerHandler']"
  name="visibility">public</attr> 

```

这个 XPath 表达式将在 `com.google.analytics.tracking.android` 包内定位 `TrackerHandler` 类，并将 `visibility` 更改为 `public`。

如果你现在构建项目，它将成功完成，但会有一些警告。在 Java 绑定项目中，尽可能修复警告是个好主意，因为它们通常表示一个类或方法被排除在绑定之外。注意以下警告：

```kt
GoogleAnalytics.Droid: Warning BG8102:
 Class GoogleAnalytics.Tracking.CampaignTrackingService has 
 unknown base type android.app.IntentService (BG8102) 
 (GoogleAnalytics.Droid)

```

要解决这个问题，在 `api.xml` 中找到 `CampaignTrackingService` 的类型定义，如下所示：

```kt
<class
   abstract="false" deprecated="not deprecated"
   extends="android.app.IntentService"
   extends-generic-aware="android.app.IntentService"
   final="false" name="CampaignTrackingService"
   static="false" visibility="public"> 

```

解决此问题的方法是将基类更改为 `Xamarin.Android` 对 `IntentService` 的定义。在 `Metadata.xml` 中添加以下代码：

```kt
<attr
   path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='CampaignTrackingService']"
   name="extends">mono.android.app.IntentService</attr> 

```

这将 `extends` 属性更改为使用 `Mono.Android.dll` 中的 `IntentService`。我通过在 Xamarin Studio 的 **程序集浏览器** 中打开 `Mono.Android.dll` 并查看 `Register` 属性找到了这个类的 Java 名称，如下面的截图所示：

![在 Java 绑定中使用 XPath](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00261.jpeg)

在 Xamarin Studio 中查看 `*.dll` 文件，你只需打开它们即可。你也可以在你的项目中的 `References` 文件夹里双击任何程序集。

如果你现在构建绑定项目，我们剩下最后一个错误，如下所示：

```kt
GoogleAnalytics.Tracking.CampaignTrackingService.cs(24,24):
 Error CS0507:
 `CampaignTrackingService.OnHandleIntent(Intent)':
 cannot change access modifiers when overriding `protected' 
 inherited member
 `IntentService.OnHandleIntent(Android.Content.Intent)'
 (CS0507) (GoogleAnalytics.Droid)

```

如果你导航到 `api.xml` 文件，你可以看到 `OnHandleIntent` 的定义如下：

```kt
<method
   abstract="false" deprecated="not deprecated" final="false"
   name="onHandleIntent" native="false" return="void"
   static="false" synchronized="false" visibility="public"> 

```

我们可以看到，这个类的 Java 方法是`public`，但基类是`protected`。因此，最好的解决办法是将 C# 版本也改为`protected`。编写一个匹配此条件的 XPath 表达式要复杂一些，但幸运的是，Xamarin 有一个简单的方法来获取它。如果你在 Xamarin Studio 的**错误**面板中双击错误消息，你会在生成的 C# 代码中看到以下注释：

```kt
// Metadata.xml XPath method reference:
   path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='CampaignTrackingService']
   /method[@name='onHandleIntent' and count(parameter)=1 and
   parameter[1][@type='android.content.Intent']]" 

```

复制`path`的值，并在`Metadata.xml`中添加以下内容：

```kt
<attr path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='CampaignTrackingService']
   /method[@name='onHandleIntent' and count(parameter)=1 and
   parameter[1][@type='android.content.Intent']]"
   name="visibility">protected</attr> 

```

现在，我们可以构建项目，并且只有与`[Obsolete]`成员被覆盖相关的警告（无需担心）。这个库现在可以用于你的`Xamarin.Android`项目中了。

但是，如果你开始使用这个库，会注意到方法的参数名称是`p0`、`p1`、`p2`等等。以下是`EasyTracker`类的几个方法定义：

```kt
public static EasyTracker GetInstance(Context p0); 
public static void SetResourcePackageName(string p0); 
public virtual void ActivityStart(Activity p0); 
public virtual void ActivityStop(Activity p0); 

```

你可以想象，在不了解正确的参数名称的情况下使用 Java 库会有多困难。之所以这样命名参数，是因为 Java 库的元数据不包括为每个参数设置正确名称的信息。因此，`Xamarin.Android`尽其所能，按顺序自动为每个参数命名。

要重命名这个类中的参数，我们可以在`Metadata.xml`中添加以下内容：

```kt
<attr path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='EasyTracker']
   /method[@name='getInstance']/parameter[@name='p0']"
   name="name">context</attr> 
<attr path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='EasyTracker']
   /method[@name='setResourcePackageName']/parameter[@name='p0']"
   name="name">packageName</attr> 
<attr path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='EasyTracker']
   /method[@name='activityStart']/parameter[@name='p0']"
   name="name">activity</attr> 
<attr path="/api/package[@name='com.google.analytics
   .tracking.android']/class[@name='EasyTracker'] 
  /method[@name='activityStop']/parameter[@name='p0']"
   name="name">activity</attr> 

```

在重新构建绑定项目时，这将有效地为`EasyTracker`类中的这四个方法重命名参数。此时，我建议你查看计划在应用程序中使用的类，并重命名这些参数，以便它们对你更有意义。你可能需要参考 Google Analytics 的文档来确保命名正确。幸运的是，SDK 中包含了一个`javadocs.zip`文件，提供了库的 HTML 参考资料。

要了解有关实现 Java 绑定的完整参考，请务必查看 Xamarin 的文档网站：[`developer.xamarin.com/guides/android/`](https://developer.xamarin.com/guides/android/)。我们在为 Google Analytics 库创建绑定时遇到的肯定还有比这更复杂的情况。

# 摘要

在本章中，我们从 Xamarin 组件商店向 Xamarin 项目添加了库，并将现有的 C# 库 Ninject 移植到了`Xamarin.iOS`和`Xamarin.Android`。接下来，我们安装了 Objective Sharpie 并探索了其生成 Objective-C 绑定的用法。最后，我们为 iOS 的 Google Analytics SDK 编写了一个功能性的 Objective-C 绑定，以及为 Android 的 Google Analytics SDK 编写了一个 Java 绑定。我们还编写了几个 XPath 表达式来清理 Java 绑定。

对于从您的 `Xamarin.iOS` 和 `Xamarin.Android` 应用程序中使用现有的第三方库，有几种可用的选项。我们从使用 Xamarin 组件商店、移植现有代码，以及设置可供 C# 使用的 Java 和 Objective-C 库等方面进行了全面了解。在下一章中，我们将介绍 `Xamarin.Mobile` 库，作为一种访问用户联系人、相机和 GPS 位置的方法。
