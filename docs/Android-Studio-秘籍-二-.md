# Android Studio 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/4884403F3172F01088859FB8C5497CF5`](https://zh.annas-archive.org/md5/4884403F3172F01088859FB8C5497CF5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：大小确实重要

本章是关于构建可以在各种设备上运行的应用程序：手机、平板、平板手机和电视。我们将连接到 YouTube 获取一些数据和视频来显示。

大小和上下文确实很重要。当然，我们可以将所有内容都放大，但这并不能真正使应用程序变得更好。平板提供的空间比手机更多，而在用户交互方面，电视与智能手机有所不同。我们如何使布局在每台设备上都能按比例缩放并看起来流畅？我们如何为每种类型的设备找到正确的方法？

在本章中，您将学习以下内容：

+   大小和上下文

+   手机、平板和平板手机布局

+   媒体播放

+   电视和媒体中心

# 大小和上下文

手机、平板、平板手机和电视等设备都配备了各种大小和形状的屏幕。我们如何从更大的屏幕中受益，或者如何为较小的屏幕提供智能导航，并在一个应用程序中保持相同的功能和代码？这就是这个第一个配方要解决的问题。

各种设备怎么样？随着可穿戴设备的推出，我们发现这些类型设备的用户行为有很大不同。同样的情况也适用于电视。一如既往，让我们先做第一步。让我们检查一个可以在手机和平板上运行的应用程序。

# 手机、平板和平板手机

手机上一个众所周知的模式是列表或回收视图，当您点击任何行时，它会显示一些详细信息。在小屏幕上，应用程序会将您导航到不同的视图。这种模式之所以存在，是因为手机屏幕上的空间不足。如果您在具有足够空间的设备上运行相同的应用程序，我们可以在屏幕的左侧显示列表，右侧显示详细信息。

多个布局是我们需要的，再加上多个片段。如果我们这样做，我们可以减少需要编写的代码量。我们不想重复自己，对吧？

片段是 Android 开发中功能强大但也经常被误解的组件。片段是（小）功能块，大多数时间都有自己的布局。使用片段容器，片段可以存在于多个位置和多个与活动相关的布局中。这就是我们如何重用功能和布局的方法。

不过，片段应该谨慎使用。如果没有合适的策略，使用片段的应用程序可能会给您带来很多麻烦。片段中的代码经常会引用活动。虽然这些代码可能仍在运行，但片段可能在中间被从活动中分离出来（例如，因为用户按下了返回按钮）。这可能导致您的应用程序崩溃。

## 准备工作

要完成此配方，您需要安装并运行 Android Studio，并且需要一部手机、平板和/或平板手机设备（一如既往，建议使用实体设备；但是您也可以使用 Genymotion 创建虚拟设备）。

由于我们将使用 YouTube Android API，您需要在设备上安装最新的 YouTube Android 应用程序。检查您的设备上是否有该应用程序，如果没有或者有更新的话，可以使用 Google Play 应用程序进行安装或更新。

最后，您需要一个开发者账户。如果您还没有一个，您需要首先从[`developer.android.com/distribute/googleplay/start.html`](http://developer.android.com/distribute/googleplay/start.html)创建一个。

除了购买本书之外，为自己购买一个开发者账户是一个非常好的投资，我强烈建议您这样做。无论如何，您都需要一个才能将您的应用程序提交到 Google Play 商店中！

## 如何做...

让我们看看如何创建我们自己的可穿戴应用程序并在设备上运行：

1.  开始一个新的 Android Studio 项目。将您的应用程序命名为`YouTubeMediaApp`，并在**公司域**字段中输入`packt.com`。然后点击**下一步**按钮。

1.  在接下来的对话框中，只选中**手机和平板电脑**选项，然后单击**下一步**按钮。

1.  在下一个对话框中，选择**空白活动**，然后单击**下一步**按钮。

1.  在**自定义活动**对话框中，单击**完成**按钮。

1.  Android Studio 将为您创建新项目。在 Android Studio 左侧的**项目**视图中，找到`app`文件夹中的`build.gradle`并打开它。

1.  在`app`文件夹中的`build.gradle`文件中添加一个依赖项到`dependencies`部分，以使用 YouTube 服务 API。我们将使用此 API 在 YouTube 上搜索视频：

```kt
compile 'com.google.apis:google-api-services-youtube:v3-rev120-1.19.0'
```

1.  同步项目（单击**立即同步**链接或使用工具栏中的**同步项目与 Gradle 文件**按钮）。

1.  打开`activity_main.xml`布局。创建一个框架布局，它将作为我们稍后要在此处显示的片段的容器。出于演示目的，我们将为其选择一个漂亮的背景颜色。让我们选择橙色：

```kt
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout xmlns:android=
  "http://schemas.android.com/apk/res/android"
   android:layout_width="match_parent"
   android:layout_height="match_parent"
   android:background="@android:color/holo_orange_light"
   android:id="@+id/main_container_for_list_fragment">
</FrameLayout>
```

1.  添加一个新布局并命名为`fragment_list.xml`。在容器内创建一个列表视图。此列表将包含我们在 YouTube 上找到的视频的标题和其他信息：

```kt
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout 
    android:orientation="vertical"     
    android:layout_width="match_parent"
    android:layout_height="match_parent">
<ListView
    android:id="@+id/main_video_list_view"
	android:visibility="visible"
	android:padding="6dp"
	android:layout_marginTop="0dp"
	android:layout_width="match_parent"
	android:layout_height="match_parent">
	</ListView>
</FrameLayout>
```

1.  添加一个新的 Java 类，命名为`ListFragment`，然后单击**确定**按钮继续。

1.  将新类设置为`Fragment`的子类，并重写`onCreate`方法。为列表视图创建一个私有成员，并按照以下代码在布局中添加对列表视图的引用：

```kt
public class ListFragment extends Fragment {
  private ListView mListView;
  @Override
  public View onCreateView(LayoutInflater inflater,    
   ViewGroup container, Bundle savedInstanceState) 
    final View view= inflater.inflate(  
      R.layout.fragment_list, container, false);
    mListView = (ListView)view.findViewById(
     R.id.main_video_list_view);
    return view;
  }
}
```

### 注意

除了`ListActivity`之外，还有一个`ListFragment`类，您可以从中继承。出于演示目的，我们将在这里从`Fragment`类继承并自行处理一些事情。

1.  在添加正确的导入语句（使用*Alt* + *Enter*快捷键或其他方式）时，您将能够选择要导入的包。您可以在`android.app.Fragment`和`android.support.v4.app.Fragment`包之间进行选择。后者仅用于向后兼容。由于我们将为我们的应用程序使用最新的 SDK，请在被询问时选择此导入语句：

```kt
import android.app.Fragment;
```

1.  为 YouTube 添加另一个私有成员和一个 YouTube 列表，并创建一个名为`loadVideos`的方法。首先，我们将初始化 YouTube 成员：

```kt
private YouTube mYoutube;
private YouTube.Search.List mYouTubeList;
private void loadVideos(String queryString){
 mYoutube = new YouTube.Builder(new NetHttpTransport(),
  new JacksonFactory(), new HttpRequestInitializer() {
   @Override
   public void initialize(HttpRequest hr) throws  
    IOException {}
 }).setApplicationName( 
  getString(R.string.app_name)).build();
}
```

1.  接下来，我们将告诉 YouTube 我们要寻找什么以及我们希望 API 返回什么信息。我们需要在`loadVideos`方法的末尾添加 try catch 结构，因为我们事先不知道是否能连接到 YouTube。将以下内容添加到`loadVideos`方法的末尾：

```kt
try{
 mYouTubeList = mYoutube.search().list("id,snippet");      
 mYouTubeList.setType("video");
 mYouTubeList.setFields( 
  "items(id/videoId,snippet/title,snippet/   
      description,snippet/thumbnails/default/url)");
}
catch (IOException e) {
  Log.d(this.getClass().toString(), "Could not 
    initialize: " + e);
}
```

1.  要使用 YouTube API，您必须首先注册您的应用程序。要这样做，请将浏览器导航到[`console.developers.google.com/project`](https://console.developers.google.com/project)。

1.  单击**创建**项目按钮。输入`YouTubeApp`作为项目名称，然后单击**创建**按钮。

1.  项目创建后，仪表板将显示在网页上。在左侧，展开**API 和身份验证**，然后单击**API**。

1.  在页面的右侧，单击 YouTube 数据 API。单击**启用 API**按钮。

1.  再次在左侧，单击 API 之后的**凭据**。在公共 API 访问下，单击**创建新密钥**按钮。

1.  在**创建新密钥**弹出对话框中，单击**Android 密钥**按钮。

1.  由于此应用仅用于演示目的，我们不需要查找所请求的**SHA1**值。只需单击**创建**按钮。

1.  现在，将为您创建一个 API 密钥。复制 API 密钥的值。

1.  在`AndroidManifest.xml`文件中，添加一个访问互联网的权限：

```kt
android:name="android.permission.INTERNET"/>
```

### 将其粘合在一起！

1.  现在回到`ListFragment`类，告诉 API 关于您的密钥，该密钥就在 YouTube 对象的`search`调用旁边：

```kt
mYouTubeList.setKey("Your API key goes here");
```

1.  创建一个新的`VideoItem`类，并添加成员以保存每个视频的请求信息。请注意，我们在这里使用 getter 和 setter：

```kt
private String title;
private String description;
private String thumbnailURL;
private String id;
public String getId() {
 return id;
}
public void setId(String id) {
 this.id = id;
}
public String getTitle() {
 return title;
}
public void setTitle(String title) {
 this.title = title;
}
public String getDescription() {
 return description;
}
public void setDescription(String description) {
 this.description = description;
}
public String getThumbnailURL() {
 return thumbnailURL;
}
public void setThumbnailURL(String thumbnail) {
 this.thumbnailURL = thumbnail;
}
```

1.  创建一个新布局并命名为`adapter_video.xml`。然后，添加文本视图以显示视频信息：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout android:layout_width="match_parent"
  android:layout_height="wrap_content"
  android:orientation="vertical"
   xmlns:android= 
    "http://schemas.android.com/apk/res/android"
  android:padding="6dp">
<TextView
  android:id="@+id/adapter_video_id"android:textSize="14sp"android:textStyle="bold"android:layout_width="match_parent"android:layout_height="wrap_content" />
<TextView
  android:id="@+id/adapter_video_title"android:textSize="20sp"android:layout_marginTop="2dp"android:layout_width="match_parent"android:layout_height="wrap_content" /></LinearLayout>
```

1.  创建一个新的`VideoAdapter`类，并使其成为`ArrayAdapter`的子类，用于保存`VideoItem`类型的条目。一个视图持有者将帮助我们用列出的`VideoItem`对象的属性填充文本视图：

```kt
public class VideoAdapter extends ArrayAdapter<VideoItem> {
 private Context mContext;
 private int mAdapterResourceId;
 public ArrayList<VideoItem>mVideos = null;
 static class ViewHolder{
        TextView videoId;
        TextView videoTitle;
    }
@Override
 public int getCount(){
 super.getCount();
 int count = mVideos !=null ? mVideos.size() : 0;
 return count;
}
public VideoAdapter (Context context, int  
 adapterResourceId, ArrayList<VideoItem> items)
{
 super(context, adapterResourceId, items);
 this.mVideos = items;
 this.mContext = context;
 this.mAdapterResourceId = adapterResourceId; 
}
@Override
public View getView(int position, View convertView, ViewGroup parent)
{
 View v = convertView;
if (v == null){LayoutInflater vi =   
     (LayoutInflater)this.getContext().getSystemService(
      Context.LAYOUT_INFLATER_SERVICE);
    v = vi.inflate(mAdapterResourceId, null);
    ViewHolder holder = new ViewHolder();
    holder.videoId = (TextView)  
     v.findViewById(R.id.adapter_video_id);
    holder.videoTitle = (TextView) 
     v.findViewById(R.id.adapter_video_title);     
    v.setTag(holder);
 }
 final VideoItem item = mVideos.get(position);
 if(item != null){
  final ViewHolder holder = (ViewHolder)v.getTag();
  holder.videoId.setText(item.getId());
  holder.videoTitle.setText( item.getTitle());
 }
 return v;
}
```

1.  现在回到`ListFragment`类。在其中再添加两个私有成员，一个用于我们找到的视频列表，一个用于我们刚刚创建的适配器：

```kt
private List<VideoItem>mVideos;
private VideoAdapter mAdapter;
```

1.  在`ListFragment`类中添加一个`search`方法：

```kt
public List<VideoItem> search(String keywords){
 mYouTubeList.setQ(keywords);
try{
   SearchListResponse response = mYouTubeList.execute();
   List<SearchResult> results = response.getItems();
   List<VideoItem>  items = new ArrayList<VideoItem>();
    for(SearchResult result:results){

    VideoItem item = new VideoItem();
    item.setTitle(result.getSnippet().getTitle());
    item.setDescription(result.getSnippet().
     getDescription());

    item.setThumbnailURL(result.getSnippet().
     getThumbnails().getDefault().getUrl());
    item.setId(result.getId().getVideoId());
    items.add(item);
  }
  return items;
 }
catch(IOException e){
  Log.d("TEST", "Could not search: " + e);
 }
}
```

1.  在`loadVideos`方法的末尾，添加调用`search`方法和初始化适配器的实现：

```kt
mVideos =search(queryString§);
mAdapter = new VideoAdapter(getActivity(), R.layout.adapter_video, (ArrayList<VideoItem>) mVideos);
```

1.  告诉列表视图关于适配器，并调用适配器的`notifyDataSetChanged`方法，通知有新条目可供显示。为此，我们将使用一个在 UI 线程上运行的`Runnable`实例：

```kt
getActivity().runOnUiThread(new Runnable() {
public void run() {
   mListView.setAdapter(mAdapter);
   mAdapter.notifyDataSetChanged();
 }
});
```

1.  现在我们将异步加载视频信息，因为我们希望应用在从互联网获取数据时能够响应。创建一个新线程，并在`run`方法内调用`loadVideos`。假设我们想要查看*Android 开发*视频：

```kt
@Override
 public void onActivityCreated(Bundle bundle){
 super.onActivityCreated(bundle);
 new Thread(new Runnable() {
   public void run(){
      loadVideos("Android development");
   }
}).start();
}
```

1.  创建一个新的布局并命名为`fragment_details.xml`。在此片段中，我们将显示用户从列表中选择的视频的缩略图和描述。既然我们已经在这里，我们也可以添加一个播放按钮。我们将在下一个步骤中需要它：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout  xmlns:android=  
 "http://schemas.android.com/apk/res/android"
android:orientation="vertical" android:layout_width="match_parent"android:layout_height="match_parent">
<Button
android:id="@+id/detail_button_play"android:text="@string/play"android:layout_width="match_parent"android:layout_height="wrap_content" />
<ImageView
android:id="@+id/detail_image"android:layout_width="match_parent"android:layout_height="wrap_content"android:src="img/gallery_thumb"/>
<TextView
android:layout_marginTop="16dp"android:id="@+id/detail_text"android:minHeight="200dp"
android:layout_width="match_parent"
android:layout_height="wrap_content" />
</LinearLayout>
```

1.  创建`DetailsFragment`类：

```kt
public class DetailsFragment  extends Fragment {
  @Override
  public View onCreateView(LayoutInflater inflater,
   ViewGroup container, Bundle savedInstanceState) {
    final View view= inflater.inflate(
      R.layout.fragment_details, container, false);
     return view;
  }
}
```

1.  在`DetailsFragment`类中添加`showDetails`私有方法。在此方法中，我们将设置描述的文本，并创建一个新的 runnable 实例来加载视频的缩略图。还添加`setVideo`方法并重写`onResume`方法：

```kt
private void showDetails(){
if (getView()!=null &&mVideo != null)
 {
   TextView tv = (TextView) 
    getView().findViewById(R.id.detail_text);
   final ImageView iv = (ImageView)    
    getView().findViewById(R.id.detail_image);
   tv.setText(mVideo.getDescription());
  new Thread(new Runnable() {
   public void run() {
      loadThumbnail(mVideo, iv);
    }
   }).start();
  }
}
public void setVideo(VideoItem video)
{
  mVideo = video;
  showDetails();
}
@Override
  public void onResume(){
  super.onResume();
  showDetails();
}
```

1.  现在，在`DetailsFragment`类中添加`loadThumbnail`方法和从给定 URL 加载缩略图图像的实现：

```kt
private void loadThumbnail(VideoItem video,final  
 ImageView iv){
try 
 {
    URL url = new URL(video.getThumbnailURL());
   final Bitmap bmp = BitmapFactory.decodeStream(   
    url.openConnection().getInputStream());

   getActivity().runOnUiThread(new Runnable() {
    public void run() {
      iv.setImageBitmap(bmp);
     }
    });
 }
 catch (Exception ex){
    Log.d(this.getClass().toString(), ex.getMessage());
 }
}
```

1.  如果用户在`ListFragment`类的列表视图中选择了一个项目，我们需要告诉`DetailFragment`显示相应的详情。在`ListFragment`类的`onCreateView`方法中，添加`onItemClick`处理程序：

```kt
mListView.setOnItemClickListener(new 
 AdapterView.OnItemClickListener() 
{
  @Override
  public void onItemClick(AdapterView<?> adapterView,    
    View view, int i, long l) 
    {
        VideoItem video = mVideos.get(i);
        onVideoClicked(video);
    }
});
return view;
```

1.  在`MainActivity`类中，添加两个静态成员，它们将代表`ListFragment`和`DetailsFragment`类的标签：

```kt
public static String TAG_LIST_FRAGMENT = "LIST";
public static String TAG_DETAILS_FRAGMENT = "DETAILS";

```

在`ListFragment`类中创建`onVideoClicked`方法。如果`DetailsFragment`存在（有一个带有`DETAILS`标签的片段），它将调用`DetailsFragment`的`showDetails`方法：

```kt
private void onVideoClicked(VideoItem video) {  
  DetailFragment detailsFragment = (DetailFragment)   
   getFragmentManager().findFragmentByTag(   
    MainActivity.TAG_DETAILS_FRAGMENT);
if (detailsFragment != null) { 
  detailsFragment.setVideo(video);}
}
```

1.  我们快要完成了。在`activity_main.xml`布局中，我们为片段创建了一个容器。现在我们将添加一些代码，以在该容器中显示`ListFragment`的内容。在`MainActivity`类中，为两个片段添加两个私有成员：

```kt
private DetailFragment mDetailsFragment;
private ListFragment mListFragment;
```

1.  创建`ListFragment`并将其添加到容器中：

```kt
mListFragment = new ListFragment();
FragmentTransaction ft =  
 getFragmentManager().beginTransaction();
ft.add(R.id.main_container_for_list_fragment, 
 mListFragment, TAG_LIST_FRAGMENT);
ft.commit();
```

1.  让我们为主活动创建另一个布局，但这次是为大屏幕，比如平板电脑。在`res`文件夹中，通过右键单击`res`项目，添加一个新的 Android 资源目录。选择**layout**作为**资源类型**，将目录命名为`layout-large`，然后单击 To 按钮。

1.  在新的`layout-large`目录中，添加一个新的布局并命名为`activity_main`。平板设备足够大，可以容纳我们的两个片段，因此对于此布局，我们将创建两个容器：一个用于列表，一个用于详情：

```kt
<?xml version="1.0" encoding="utf-8"?><FrameLayout xmlns:android=  
 "http://schemas.android.com/apk/res/android"
android:layout_width="match_parent"android:layout_height="match_parent"android:id="@+id/main_container">
<FrameLayout
android:layout_width="300dp"
android:layout_height="match_parent"
android:background="@android:color/holo_orange_light"
android:id="@+id/main_container_for_list_fragment">
</FrameLayout>
<FrameLayout
android:id="@+id/main_container_for_detail_fragment"android:background="@android:color/holo_blue_light"
android:layout_marginLeft="300dp"
android:layout_width="match_parent"
android:layout_height="match_parent">
</FrameLayout>
</FrameLayout>
```

1.  修改`MainActivity`的`onCreate`实现。如果容器可用，我们也将加载详情片段。将`commit`调用移到最后：

```kt
mListFragment = new ListFragment();
FragmentTransaction ft =  
 getFragmentManager().beginTransaction();
ft.add(R.id.main_container_for_list_fragment,  mListFragment, TAG_LIST_FRAGMENT);
if (findViewById(  
 R.id.main_container_for_detail_fragment)!= null){
  mDetailsFragment = new DetailFragment();ft.add(R.id.main_container_for_detail_fragment,  
  mDetailsFragment, TAG_DETAILS_FRAGMENT);
}
ft.commit();
```

1.  还有一件事，如果你允许我解释。嗯，实际上有几件事。如果应用正在手机上运行，我们需要从列表片段视图导航到详情片段视图。修改`MainActivity`文件中的`onVideoClicked`方法，以便在那里创建详情片段：

```kt
private void onVideoClicked(VideoItem video) {
  DetailFragment detailsFragment = (DetailFragment)    
   getFragmentManager().findFragmentByTag(  
    MainActivity.TAG_DETAILS_FRAGMENT);
 if (detailsFragment != null) {
   detailsFragment.setVideo(video);
 }
 else
 {
   FragmentTransaction ft =  getFragmentManager().beginTransaction();
   detailsFragment = new DetailFragment();
   ft.add(R.id.main_container_for_list_fragment,  
    detailsFragment, MainActivity.TAG_DETAILS_FRAGMENT);
   ft.addToBackStack(MainActivity.TAG_DETAILS_FRAGMENT); 
   ft.commit();
   detailsFragment.setVideo(video);
 }
}
```

1.  我们在上一步中添加的`addToBackStack`调用通知片段管理器所有片段都在堆栈上，因此我们可以提供导航方式。我们需要告诉我们的活动在按下返回按钮时如何行为：我们想离开活动还是我们想从堆栈中弹出一个片段？我们将覆盖`MainActivity`的`onBackPressed`方法，就像这样：

```kt
@Override 
public void onBackPressed() {
if (getFragmentManager().getBackStackEntryCount()>0){
        getFragmentManager().popBackStack();
    }
else {
this.finish();
    }
}
```

我们完成了！我们有一些工作要做，但现在我们有一个可以在具有导航的手机上运行并且如果有足够的空间将显示两个片段的应用程序，就像平板电脑一样。

为了查看差异，请在智能手机和平板电脑上运行应用程序。在手机上，它将类似于以下屏幕截图。在平板电脑上（如果您没有可用的平板电脑，可以使用 Genymotion），列表和详细信息都显示在单个视图中：

![粘合在一起！](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_05_02.jpg)

## 还有更多…

下一个教程将展示如何实现允许我们观看刚刚找到的视频的功能。毕竟，播放视频是我们想要的！

# 媒体播放

在上一个教程中，我们从 YouTube 检索了搜索结果，并在列表和详细片段中显示了它们。找到的条目代表视频，因此如果我们能够在应用程序中播放它们，那将是很好的。让我们找到一种方法来做到这一点。

由于我们知道视频 ID，因此很容易为其组合 URL 并在 web 视图中加载它们；但是，Google 为此提供了更简单的解决方案，并为此提供了 YouTube Android Player API。它有一些限制，但足够有趣。

## 准备工作

要完成本教程，您需要完成上一个教程，因为本教程从上一个教程结束的地方开始。虽然我建议您在物理手机和平板电脑上测试应用程序，但您当然也可以使用 Genymotion。

如果您使用虚拟设备，那么谷歌应用程序（以及 API 和播放器所依赖的 YouTube 应用程序）将丢失，并且该应用程序将因此失败。您需要首先在虚拟设备上下载并安装它们。

## 如何做…

让我们看看如何通过以下步骤扩展应用程序，以便为我们播放视频：

1.  从[`developers.google.com/youtube/android/player/downloads`](https://developers.google.com/youtube/android/player/downloads)下载 YouTube Player API。

1.  在下载的文件中，在`libs`文件夹中找到`YouTubeAndroidPlayerApi.jar`文件并复制它。

1.  从上一个教程中打开项目。

1.  在`app`模块中的`libs`文件夹中找到`libs`文件夹，并粘贴`YouTubeAndroidPlayerApi.jar`文件。

1.  `build.gradle`文件中的依赖项可能已经准备好包括`lib`文件中的任何文件；但是如果没有，添加依赖项：

```kt
compile fileTree(dir: 'libs', include: ['YouTubeAndroidPlayerApi.jar'])
```

1.  单击立即同步链接，或者如果它没有出现，请单击工具栏上的**使用 Gradle 文件同步项目**按钮。

1.  在`MainActivity`类中，添加一个用于将要创建的播放器片段的静态标签。还添加`YouTubePlayerFragment`的私有成员和一个公共成员来存储 YouTube 播放器，如果初始化成功的话：

```kt
public static String TAG_PLAYER_FRAGMENT = "PLAYER";
private YouTubePlayerFragment mPlayerFragment;
public YouTubePlayer mYouTubePlayer = null;
```

1.  在`layout-large`目录中打开`activity_main.xml`，将详细片段的高度更改为`300dp`，并将`YouTubePlayerFragment`添加到其中。预览可能会抱怨，因为它不知道应该如何渲染，但只要包被识别，这并不是真正的问题，如果您已成功完成步骤 5 和 6，那么包将被识别：

```kt
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout
android:layout_width="match_parent"android:layout_height="match_parent"android:id="@+id/main_container">
<FrameLayout
android:layout_width="300dp"android:layout_height="match_parent"android:background="@android:color/holo_orange_light"android:id="@+id/main_container_for_list_fragment"></FrameLayout>
<FrameLayout
android:id="@+id/main_container_for_detail_fragment"android:background="@android:color/holo_blue_light"android:layout_marginLeft="300dp"android:layout_width="match_parent"android:layout_height="300dp"></FrameLayout>
<fragment
android:name="com.google.android.youtube.player.YouTubePlayerFragment"
android:id="@+id/main_youtube_player_fragment"android:layout_marginTop="300dp"android:layout_marginLeft="300dp"android:layout_width="match_parent"android:layout_height="match_parent"android:layout_weight="3"/>
</FrameLayout>
```

1.  在`onCreateView`中，在`ft.commit`之前，找到播放器片段的容器并初始化`YouTuberPlayer`：

```kt
mPlayerFragment = (YouTubePlayerFragment)  
 getFragmentManager().findFragmentById(
  R.id.main_youtube_player_fragment);if (mPlayerFragment != null) {
  ft.add(mPlayerFragment, TAG_PLAYER_FRAGMENT);  mPlayerFragment.initialize("Your API key", new 
   YouTubePlayer.OnInitializedListener() 
  {
   @Override 
     public void onInitializationSuccess( YouTubePlayer.Provider   
     provider, YouTubePlayer youTubePlayer, boolean isRestored) 
   {
     mYouTubePlayer = youTubePlayer;}
   @Override 
    public void onInitializationFailure(YouTubePlayer.Provider    
    provider, YouTubeInitializationResult 
     youTubeInitializationResult) {
      Log.d(this.getClass().toString(),   
       youTubeInitializationResult.toString()); 
 });
}
```

1.  在`DetailFragment`中，在`onCreateView`方法中为播放按钮添加一个点击处理程序，就在返回视图对象之前：

```kt
view.findViewById(R.id.detail_button_play).setOnClickListener(
 new View.OnClickListener() {
  @Override
  public void onClick(View v) {
    playVideo();}
});
```

1.  在`DetailFragment`中创建`playVideo`方法。如果播放器片段存在（在大屏幕设备上），并且已经初始化，它将播放视频；如果不存在（在小屏幕设备上），我们将创建一个播放器片段，初始化它，并将其添加到堆栈中：

```kt
private void playVideo(){
if (getActivity() != null && 
 ((MainActivity)getActivity()).mYouTubePlayer != null){
    ((MainActivity)getActivity()  
     ).mYouTubePlayer.cueVideo(mVideo.getId());
 }
 else {
    FragmentTransaction ft =  
     getFragmentManager().beginTransaction();
    YouTubePlayerFragment playerFragment = new 
    YouTubePlayerFragment();
   ft.add(R.id.main_container_for_list_fragment,   
    playerFragment, MainActivity.TAG_DETAILS_FRAGMENT);
   ft.addToBackStack(MainActivity.TAG_PLAYER_FRAGMENT);
   ft.commit();
   playerFragment.initialize("Your API key", new 
    YouTubePlayer.OnInitializedListener() {
      @Override
     public void onInitializationSuccess(YouTubePlayer.Provider 
       provider, YouTubePlayer youTubePlayer, boolean 
       isRestored) {
         if (!isRestored) {
             youTubePlayer.cueVideo(mVideo.getId());
          }
      }
      @Override
	   public void onInitializationFailure(YouTubePlayer.Provider 
       provider, YouTubeInitializationResult 
        youTubeInitializationResult) {
        Log.d(this.getClass().toString(),   
         youTubeInitializationResult.toString()); 
      }
   });
 }
}
```

通过这样，我们已经添加了一个简单但完全功能的实现来播放所选视频。

## 还有更多...

有许多选项可用于播放视频，例如全屏或原位播放，带按钮或不带按钮等。使用 Chrome Cast，媒体也可以发送到您的电视上，或者正如我们将在最后的食谱中看到的那样，我们可以为 Android TV 创建一个应用程序。

# 电视和媒体中心

无聊！电视上又没有什么好看的！至少没有什么看起来足够有趣的东西。运行在 Android 上的智能电视为开发者创造了一个全新有趣的世界。最终，我们得到了我们应得的屏幕尺寸！

然而，它也拥有不同类型的受众。用户与他们的手机和平板电脑的互动程度非常高。当涉及观看电视时，焦点更多地放在消费上。

好吧，电视上有什么？泡杯茶，开始观看节目。偶尔，用户可能对一些互动感兴趣（这种现象大多出现在第二屏应用程序中，因为并非每个人都拥有智能电视），但大多数时候，电视观众只是想靠在椅子上放松。

## 准备工作

这个食谱需要 Android Studio 正常运行和安装最新的 SDK。在这个食谱中，我们将为您提供一个关于电视应用程序的简要介绍。只需几个步骤，我们就可以创建一个媒体中心应用程序。不用担心，您不需要拥有 Android 电视。我们将创建一个虚拟的电视。

## 如何做...

让我们看看开发 Android TV 应用程序需要做什么：

1.  在 Android Studio 中创建一个新项目。将其命名为`PersonalTeeVee`，然后点击“下一步”按钮。

1.  选择电视选项，然后点击“下一步”按钮。

1.  选择 Android TV Activity，然后点击下一步。

1.  在“Activity Name”字段中输入`TeeVeeActivity`，在“Title”字段中输入`Personal Tee Vee`，然后点击“完成”按钮。

1.  Android Studio 为您创建了一个手机和一个电视模块。将配置更改为电视。您将看到如下图所示的内容：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_05_04.jpg)

1.  查看电视模块中的`AndroidManifest.xml`文件。注意“lean back”功能要求（告诉我们这是一个全屏体验的电视应用程序，没有任何重型互动，基本上是关于消费内容，比如观看视频）。还要注意我们不需要触摸屏。电视屏幕离得太远了，无法触摸。此外，没有人喜欢电视屏幕上的污渍：

```kt
<uses-feature
android:name="android.hardware.touchscreen"
android:required="false" />
<uses-feature
android:name="android.software.leanback"
android:required="true" />
```

1.  要测试电视应用程序，我们需要有一个虚拟电视设备。从“工具”|“Android”菜单中打开“AVD 管理器”选项。

1.  点击“创建虚拟设备”按钮。

1.  从类别列表中选择电视，并选择一个电视设备（1080p 或更高）。然后点击“下一步”按钮。

1.  选择一个系统镜像。例如，我选择了**API 级别 22 x86**。点击“下一步”。

1.  修改 AVD 的名称为您认为最合适的名称，然后点击“完成”按钮。将为您创建一个新的虚拟电视设备。

1.  点击播放按钮启动您的电视设备。如果它说**Google Play 服务已停止**，您现在可以忽略这条消息（尽管如果您想播放视频，您将需要它）。

1.  一旦设备启动，从 Android Studio 运行您的电视应用程序。默认情况下，它看起来像这样：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_05_05.jpg)

哇，这已经是一个完全功能的媒体中心应用程序了！

这只是一个简短的介绍，介绍了如何构建 Android TV 应用程序。玩玩它，调整一下。

## 还有更多...

虽然这个食谱中的应用程序专门用于电视，但我认为您没有理由不能将其制作成任何类型的设备的应用程序：手机、平板电脑和电视。如果您愿意，您可以将本章中的所有食谱合并为一个单一的应用程序。这是一个不错的挑战，不是吗？

除了 YouTube 之外，还有一些有趣的与媒体相关的 API 可以调查。例如，在[www.programmableweb.com](http://www.programmableweb.com)上，你可以找到一些有趣的 API。以下是其中一些：

| API | 导航 |
| --- | --- |
| YouTube | http://www.programmableweb.com/api/youtube-live-streaming |
| Vimeo | http://www.programmableweb.com/api/vimeo |
| Hey! Spread | http://www.programmableweb.com/api/heyspread |
| Pirateplay | http://www.programmableweb.com/api/pirateplay |
| Tinysong | http://www.programmableweb.com/api/tinysong |
| TwitVid | http://www.programmableweb.com/api/twitvid |

现在我们知道从哪里获取媒体项目，如何播放它们，以及如何自动创建媒体中心应用程序了。

接下来：让我们通过捕捉一些图像来创建一些媒体。下一章见！

## 另请参阅

+   第六章，*捕捉和分享*


# 第六章：捕捉和分享

我们喜欢与他人分享我们生活的世界，所以我们将使用我们的智能手机拍摄我们关心的所有事物和所有人的图像或视频。在 Android 上，这相当容易。

在本章中，你将学习以下内容：

+   以简单的方式捕捉图像

+   使用 Camera2 API 进行图像捕捉

+   图像分享

+   方向问题

# 介绍

作为开发者，你可以启动一个意图，获取数据，并对其进行任何你想要的操作。

如果你想自己处理图像或视频捕捉，事情会变得有点复杂。那么，为什么有人要这样做呢？这给了我们更多的灵活性，以处理相机的预览、过滤或处理方式。

从 Android Lollipop 开始，我们一直在使用的旧相机 API 已被 Camera2 API 取代，这被证明是一个巨大的改进。不幸的是，一些方向问题仍然存在，主要是由于 Android 硬件和软件的大碎片化。在一些设备上，捕获的图像似乎被旋转了 90 度。为什么会这样？你将在本章的最后一个配方中找到答案。

# 以简单的方式捕捉图像

当然，在 Android 上有许多拍照或录像的方式。捕捉图像的最简单方式是使用意图启动相机应用程序，并在拍摄完成后获取结果。

## 准备工作

对于这个配方，你只需要运行 Android Studio。

## 如何做...

启动相机意图通常是这样的：

1.  在 Android Studio 中，创建一个新项目。

1.  在`activity_main.xml`布局中，添加一个新按钮和一个图像视图。将图像视图命名为`image`。

1.  为该按钮创建一个点击处理程序。

1.  从事件处理程序实现中调用`takePicture`方法。

1.  实现`takePicture`方法。如果设备支持，启动捕捉意图：

```kt
static final int REQUEST_IMAGE_CAPTURE = 1;
private void takePicture() {
  Intent captureIntent = new  
    Intent(MediaStore.ACTION_IMAGE_CAPTURE);
  if (captureIntent.resolveActivity(  
   getPackageManager()) != null) {
    startActivityForResult(captureIntent,   
       REQUEST_IMAGE_CAPTURE);
   }
}
```

1.  重写`onActivityResult`方法。你将从返回的数据中获取缩略图，并在图像视图中显示结果：

```kt
@Override 
  protected void onActivityResult(int requestCode, int resultCode, Intent data) { 
   if (requestCode == REQUEST_IMAGE_CAPTURE &&resultCode == RESULT_OK) {     
        Bundle extras = data.getExtras();
        Bitmap thumbBitmap = (Bitmap)  
         extras.get("data");");
         ((ImageView)findViewById(R.id.image) 
         ).setImageBitmap(thumbBitmap);
    }
}
```

这是捕捉图像的最简单方式，也许你以前已经这样做过了。

## 还有更多...

如果你想在自己的应用程序中预览图像，还有更多工作要做。Camera2 API 可用于预览、捕捉和编码。

在 Camera2 API 中，你会找到诸如`CameraManager`、`CameraDevice`、`CaptureRequest`和`CameraCaptureSession`之类的组件。

以下是最重要的 Camera2 API 类：

| 类 | 目标 |
| --- | --- |
| `CameraManager` | 选择相机，创建相机设备 |
| `CameraDevice` | `创建 CaptureRequest`，`CameraCaptureSession` |
| `CaptureRequest, CameraBuilder` | 链接到表面视图（预览） |
| `CameraCaptureSession` | 捕捉图像并在表面视图上显示 |

我们将在下一个配方“图像捕捉”中调查的示例可能一开始看起来有点令人困惑。这主要是因为设置过程需要许多步骤，大部分将以异步方式执行。但不要担心，我们将逐步调查它。

# 使用 Camera2 API 进行图像捕捉

让我们与我们所爱的人分享我们周围的世界。一切都始于预览和捕捉。这就是这个配方的全部内容。我们还将回到那些旧日的照片是棕褐色调的好日子。

有许多应用程序，比如 Instagram，提供了添加滤镜或效果到你的照片的选项。如果棕褐色是过滤和分享照片的唯一选项，会发生什么？也许我们可以设置一个趋势。#每个人都喜欢棕褐色！

我们将使用 Camera2 API 来捕捉图像，基于 Google 在 GitHub 上提供的 Camera2 Basic 示例。作为配方步骤的参考，你可以查看以下类图。它将清楚地显示我们正在处理的类以及它们之间的交互方式：

![使用 Camera2 API 进行图像捕捉](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_01.jpg)

我们将调查其中的具体情况，一旦您找出了问题所在，我们将通过使预览和捕获的图像呈现为棕褐色（或者，如果您愿意，可以选择其他效果）来为其添加一些我们自己的东西。

## 准备工作

对于这个示例，我们将使用 Camera2 API。由于我们将使用此 API，您需要使用运行 Android 5.0 或更高版本（推荐）的真实设备，或者您需要创建一个虚拟设备。

## 操作步骤...

让我们看看如何快速上手。Google 已经为我们准备了一个整洁的示例：

1.  在 Android Studio 中，从启动向导中选择**导入 Android 代码示例**，或者在**文件**菜单上选择**导入示例**。

1.  在下一个对话框中，您将看到许多有趣的示例应用程序，展示了各种 Android 功能。选择**Camera2 Basic**示例，然后点击**Next**按钮：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_02.jpg)

1.  将项目命名为`EverybodyLovesSepia`，然后点击**Finish**按钮。

### 注意

如果点击按钮后什么都没有发生（由于 Android Studio 的某些版本中存在的错误），请再试一次，但这次保持项目名称不变。

1.  Android Studio 将为您从 GitHub 获取示例项目。您可以在[`github.com/googlesamples/android-Camera2Basic`](https://github.com/googlesamples/android-Camera2Basic)找到它。

1.  在设备上或虚拟设备上运行应用程序。

### 注意

如果您正在使用 Genymotion 上运行的虚拟设备，请首先通过单击右侧的相机图标，打开相机开关，并选择（网络）相机来启用相机。

在应用程序中，您将看到相机的预览，如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_03.jpg)

许多事情又自动发生了！这个 Camera2 API 示例中有什么？需要什么来捕获图像？实际上，需要相当多的东西。打开`Camera2BasicFragment`类。这就是大部分魔术发生的地方。

### 折叠所有方法

为了创建一个不那么压倒性的视图，折叠所有方法：

1.  您可以通过从**Code**菜单中选择**Folding**选项来做到这一点。在子菜单中，选择**Collapse all**。

1.  您还会在此子菜单中找到其他选项；例如，**展开所有**方法或**展开**（仅展开所选方法）。

### 提示

使用快捷键*Cmd*后跟*+*和*Cmd*后跟*–*（或者*Ctrl*后跟*+*和*Ctrl*后跟*–*对于 Windows）来展开或折叠一个方法。使用快捷键*Cmd* + *Shift*后跟*+*和*Cmd* + *Shift*后跟*–*（*Ctrl* + *Shift*和*+*和*Shift* + *Ctrl*和*–*对于 Windows）来展开或折叠类中的所有方法。

1.  展开`onViewCreated`方法。在这里，我们看到了`mTextureView`的初始化，它是对自定义小部件`AutoFitTextureView`的引用。它将显示相机预览。

1.  接下来，展开`onResume`方法。最初，这是设置`SurfaceTextureListener`类的地方。正如示例中的注释已经建议的那样，这允许我们在尝试打开相机之前等待表面准备就绪。双击`mSurfaceTextureListener`，使用快捷键*Cmd* + *B*（对于 Windows，是*Ctrl* + *B*）跳转到其声明，看看这是怎么回事。

1.  完全展开`mSurfaceTextureListener`的初始化。就像活动一样，纹理视图也有一个生命周期。事件在这里被处理。目前，这里最有趣的是`onSurfaceTextureAvailable`事件。一旦表面可用，将调用`openCamera`方法。双击它并跳转到它。

1.  `openCamera`方法中发生了许多事情。调用了`setUpCameraOutputs`方法。此方法将通过设置私有成员`mCameraId`和图像的（预览）大小来处理要使用的相机（如果有多个）。这对于每种类型的设备可能是不同的。它还会处理宽高比。几乎任何设备都支持 4:3 的宽高比，但许多设备也支持 16:9 或其他宽高比。

### 注意

大多数设备都有一到两个摄像头。有些只有一个后置摄像头，有些只有一个前置摄像头。前置摄像头通常支持较少的图像尺寸和宽高比。

另外，随着 Android Marshmallow（Android 6.0）带来的新权限策略，您的应用程序可能根本不被允许使用任何摄像头。这意味着您始终需要测试您的应用程序是否可以使用摄像头功能。如果不能，您将需要通过显示对话框或 toast 向用户提供一些反馈。

1.  接下来，让我们看一下`openCamera`方法中的以下行。它说要打开`setCameraOutputs`方法为我们选择的相机：

```kt
manager.openCamera(mCameraId, mStateCallback, mBackgroundHandler);
```

1.  它还提供了一个`mStateCallback`参数。如果您双击它并跳转到它，您可以看到它的声明。这里的事情再次是异步发生的。

1.  一旦相机被打开，预览会话将会开始。让我们跳转到`createCameraPreviewSession`方法。

1.  看一下`mCameraDevice.createCaptureSession`。进入该方法的一个参数是捕获会话状态回调。它用于确定会话是否成功配置，以便可以显示预览。

1.  现在，需要做什么来拍照？找到`onClick`方法。您会注意到调用`takePicture`方法。跳转到它。`takePicture`方法又调用`lockFocus`方法。跳转到它。

1.  拍照涉及几个步骤。相机的焦点必须被锁定。接下来，需要创建一个新的捕获请求并调用`capture`方法：

```kt
mCaptureSession.capture(mPreviewRequestBuilder.build(),  
 mCaptureCallback, mBackgroundHandler);
```

1.  进入`capture`方法的一个参数是`mCaptureCallback`。使用*Cmd* + *B*（或 Windows 的*Ctrl* + *B*）跳转到它的声明。

1.  您会注意到两个方法：`onCaptureProgressed`和`onCaptureCompleted`。它们都调用私有方法`process`并将结果或部分结果传递给它。

1.  `process`方法将根据各种可能的状态而有所不同。最后，它将调用`captureStillPicture`方法。使用*Cmd* + *B*（或 Windows 的*Ctrl* + *B*）跳转到它的声明。

1.  `captureStillPicture`方法初始化了一个`CaptureRequest.Builder`类，用于拍照并以正确的属性存储照片，例如方向信息。一旦捕获完成并且文件已保存，相机焦点将被解锁，并通过 toast 通知用户：

```kt
CameraCaptureSession.CaptureCallback CaptureCallback= new CameraCaptureSession.CaptureCallback() {
    @Override
    public void onCaptureCompleted 
     (CameraCaptureSession session, 
         CaptureRequest request, TotalCaptureResult  
          result) {
           showToast("Saved: " + mFile);
          unlockFocus();
       }
};
```

前面的步骤向您展示了基本的 Camera2 示例应用程序的亮点。为了在您的应用程序中拍照，需要做相当多的工作！如果您不需要在应用程序中进行预览，您可能希望考虑使用意图来拍照。但是，拥有自己的预览可以为您提供更多的控制和效果的灵活性。

### 添加深褐色效果

我们将在预览中添加一个深褐色效果，只是因为它看起来很酷（当然，一切在早期都更好），使用以下步骤：

1.  转到`createCameraPreviewSession`方法，并在相机捕获会话状态回调实现的`onConfigured`类内部，在设置`autofocus`参数之前添加这一行：

```kt
mPreviewRequestBuilder.set(
 CaptureRequest.CONTROL_EFFECT_MODE,  
  CaptureRequest.CONTROL_EFFECT_MODE_SEPIA);
```

1.  如果您现在运行您的应用程序，您的预览将是深褐色。但是，如果您按下按钮来捕获图像，它将不会产生这种效果。在`onCaptureStillPicture`方法中，您将不得不做同样的事情。在设置`autofocus`参数的行的上面添加这一行：

```kt
captureBuilder.set(   
 CaptureRequest.CONTROL_EFFECT_MODE,  
  CaptureRequest.CONTROL_EFFECT_MODE_SEPIA);
```

再次运行您的应用程序，捕捉一张图像，并使用 Astro 应用程序（或其他文件浏览器应用程序）找到捕捉的文件。您可以在`Android/data/com.example.android.camera2basic`找到它（显然，如果您接受了建议的包名称，否则路径将包括您提供的包名称）。它是泛黄的！

如果您愿意，您还可以尝试一些其他可用效果的负面实验，这也很有趣，至少有一段时间。

目前就是这样。我们还没有做太多的编程，但我们已经看了一些有趣的代码片段。在下一个教程中，我们将在 Facebook 上分享我们捕捉的图像。

## 还有更多...

欲了解更多信息，请访问 GitHub [`github.com/googlesamples/android-Camera2Basic`](https://github.com/googlesamples/android-Camera2Basic) 和 Google Camera2 API 参考 [`developer.android.com/reference/android/hardware/camera2/package-summary.html`](https://developer.android.com/reference/android/hardware/camera2/package-summary.html)。

您可以在[`github.com/ChristianBecker/Camera2Basic`](https://github.com/ChristianBecker/Camera2Basic)找到一个有趣的 Camera2 API 示例的分支，支持 QR 码扫描。

# 图像分享

图像捕捉如果没有分享图像的能力就不好玩；例如，在 Facebook 上。我们将使用 Facebook SDK 来实现这一点。

挑战！如果您正在构建一个在 Parse 后端上运行的应用程序，就像我们在第二章中所做的那样，*云端后端的应用程序*，那就没有必要了，因为 Facebook SDK 已经在其中了。如果您愿意，您可以将第二章的教程与本教程结合起来，快速创建一个真正酷的应用程序！

## 准备工作

对于这个教程，您需要成功完成上一个教程，并且需要有一个真正的 Android 设备（或虚拟设备，但这将需要一些额外的步骤）。

您还需要一个 Facebook 账户，或者您可以只为测试目的创建一个。

## 操作步骤...

让我们看看如何在 Facebook 上分享我们的泛黄捕捉的图像：

1.  从上一个教程中获取代码。打开`app`文件夹中的`build.gradle`文件。在`dependencies`部分添加一个新的依赖项，并在添加了这行代码后点击**立即同步**链接：

```kt
compile 'com.facebook.android:facebook-android-sdk:4.1.0'

```

1.  要获取 Facebook 应用程序 ID，请浏览[`developers.facebook.com`](https://developers.facebook.com)（是的，这需要一个 Facebook 账户）。从**MyApps**菜单中，选择**添加新应用**，选择**Android**作为您的平台，输入您的应用名称，然后点击**创建新的 Facebook 应用程序 ID**。选择一个类别-例如，**娱乐**-然后点击**创建应用程序 ID**。

1.  您的应用程序将被创建，并显示一个快速入门页面。向下滚动到**告诉我们关于您的 Android 项目**部分。在**包名称**和**默认活动类名称**字段中输入详细信息，然后点击**下一步**按钮。

1.  将显示一个弹出警告。您可以放心地忽略警告，然后点击**使用此包名称**按钮。Facebook 将开始思考，一段时间后**添加您的开发和发布密钥哈希**部分将出现。

1.  要获取开发密钥哈希，打开终端应用程序（在 Windows 中，启动命令提示符）并输入以下内容：

```kt
keytool -exportcert -alias androiddebugkey -keystore ~/.android/debug.keystore | openssl sha1 -binary | openssl base64
```

### 提示

如果提示输入密钥库密码，请输入`android`，这应该就可以了 - 除非您之前已更改了密码。

1.  点击*Enter*，复制显示的值，并粘贴到 Facebook 网页的**开发密钥哈希**中。点击**下一步**按钮继续。

1.  在**下一步**部分，点击**跳转到开发者仪表板**按钮。它会直接带你到你需要的信息，即应用 ID。复制**应用 ID**字段中的值：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_04.jpg)

1.  接下来，初始化 Facebook SDK。打开`CameraActivity`类，在`onCreate`方法中，在`super.OnCreate`行后添加以下行。使用*Alt* + *Enter*快捷键导入所需的包`com.facebook.FacebookSdk`：

```kt
FacebookSdk.sdkInitialize(getApplicationContext());
```

1.  现在我们需要告诉应用关于 Facebook 应用 ID 的信息。打开`res/values`文件夹中的`strings.xml`文件。添加一个包含你的 Facebook 应用 ID 的新字符串：

```kt
<string name="facebook_app_id">Your facebook app id</string>
```

1.  打开`AndroidManifest.xml`文件。

1.  在`application`元素中添加一个元数据元素：

```kt
<meta-data android:name="com.facebook.sdk.ApplicationId" android:value="@string/facebook_app_id"/>
```

1.  在`manifest`文件中添加一个`FacebookActivity`声明：

```kt
<activity android:name="com.facebook.FacebookActivity"android:configChanges="keyboard|keyboardHidden|screenLayout|   
   screenSize|orientation"
  android:theme="@android:style/Theme.Translucent.
   NoTitleBar"
  android:label="@string/app_name" />
```

1.  在`Camera2BasicFragment`类中，找到`captureStillPicture`方法。在`onCaptureCompleted`回调实现的末尾添加一个新的调用，就在`unlockFocus`类后面：

```kt
sharePictureOnFacebook();
```

1.  最后，在`manifest`文件中的`application`部分添加一个提供者，这将允许你在 Facebook 上分享图片。下一章将讨论内容提供者。现在只需在`authorities`的`FaceBookContentProvider`末尾添加你的应用 ID，替换示例中的零：

```kt
<provider android:authorities="com.facebook.app. 
  FacebookContentProvider000000000000"android:name="com.facebook.FacebookContentProvider"android:exported="true" />
```

1.  实现`sharePictureOnFacebook`方法。我们将从文件中加载位图。在真实的应用中，我们需要计算`inSampleSize`的所需值，但为了简单起见，我们在这里只使用固定的`inSampleSize`设置为`4`。在大多数设备上，这将足以避免其他情况下可能发生的任何`OutOfMemory`异常。此外，我们将在拍照后显示的`share`对话框中添加照片：

```kt
private void sharePictureOnFacebook(){
    final BitmapFactory.Options options = new  
     BitmapFactory.Options();
    options.inJustDecodeBounds = false;
    options.inSampleSize = 4;
    Bitmap bitmap =  
     BitmapFactory.decodeFile(mFile.getPath(), options); 
    SharePhoto photo = new  
    SharePhoto.Builder().setBitmap(bitmap).build();
    SharePhotoContent content = new  
    SharePhotoContent.Builder().addPhoto(photo).build();
    ShareDialog.show(getActivity(), content);
}
```

1.  为了安全起见，我们希望为每张图片创建一个唯一的文件名。修改`onActivityCreated`方法以实现这一点：

```kt
@Override
public void onActivityCreated(Bundle savedInstanceState) {
    super.onActivityCreated(savedInstanceState);
    mFile = new 
    File(getActivity().getExternalFilesDir(null),  
      "pic"+ new Date().getTime()+".jpg");
}
```

1.  在你的 Facebook 时间轴上，页面会显示如下。这里是用荷兰语显示的：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_05.jpg)

1.  运行应用程序，在你自己的 Facebook 时间轴上分享一些棕褐色的图片！

我们的应用已经完全可用，尽管可能需要一些调整。在我的三星设备上，我以竖屏模式拍摄的所有图像都旋转了 90 度。这有点太艺术了。让我们在下一个示例中修复它！

# 方向问题

在一些设备上（如三星设备），以竖屏模式捕获的图像会旋转 90 度；而在其他设备上（如 Nexus 设备），情况似乎很好。例如，如果你使用 Astro 应用查看文件，你可能不会注意到这一点，但如果你在 Facebook 的**share**对话框中预览，你就会注意到。

这是许多 Android 开发者都面临的一个众所周知的挑战。图像可能包含有关旋转角度的元数据，但显然并不是每个应用都尊重这些元数据。最好的解决方案是什么？每次显示图像时都应该旋转图像吗？应该旋转位图本身，这可能非常耗时和占用处理器吗？

## 做好准备

对于这个示例，你需要成功完成之前的示例。最好如果你有多个 Android 设备来测试你的应用。否则，如果你至少有一台三星设备可用，那就太好了，因为这个品牌的大多数（如果不是全部）型号都可以重现方向问题。

## 操作步骤

让我们看看如果出现这个方向问题，你如何解决它：

1.  在 Facebook 的**share**对话框中，预览图像会旋转 90 度（在一些设备上），如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_06.jpg)

1.  这看起来不像我生活的世界。在我的三星 Galaxy Note 3 设备上是这样的，但在我的 Nexus 5 设备上不是。显然，三星将图片存储为从横向角度看的样子，然后向其中添加元数据以指示图像已经旋转（与默认方向相比）。然而，如果你想在 Facebook 上分享它，事情就会出错，因为元数据中的方向信息没有得到尊重。

1.  因此，我们需要检查元数据，并找出其中是否有旋转信息。添加`getRotationFromMetaData`方法：

```kt
private int getRotationFromMetaData(){
   try {
      ExifInterface exif = new 
      ExifInterface(mFile.getAbsolutePath());
      int orientation = exif.getAttributeInt(
       ExifInterface.TAG_ORIENTATION,
        ExifInterface.ORIENTATION_NORMAL);
      switch (orientation) {
		  case ExifInterface.ORIENTATION_ROTATE_270:
                return 270;
          case ExifInterface.ORIENTATION_ROTATE_180:
                return 180;case ExifInterface.ORIENTATION_ROTATE_90:
                return 90;
          default:
                return 0;
      }
   }
   catch (IOException ex){
       return 0;
   }
}
```

1.  如果需要，您必须在显示共享预览之前旋转位图。这就是`rotateCaptureImageIfNeeded`方法的用处。

在这里，我们可以安全地在内存中旋转位图，因为`inSampleSet`值为`4`。如果旋转原始全尺寸位图，很可能会耗尽内存。无论哪种方式，都会耗费时间，并导致捕获图像和显示共享预览对话框之间的延迟：

```kt
private Bitmap rotateCapturedImageIfNeeded(Bitmap bitmap){
    int rotate = getRotationFromMetaData();
    Matrix matrix = new Matrix();
    matrix.postRotate(rotate);
    bitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(),
     bitmap.getHeight(), matrix, true);
    Bitmap mutableBitmap = bitmap.copy(Bitmap.Config.ARGB_8888,  
     true);
   return mutableBitmap;
}
```

1.  然后，在`sharePictureOnFacebook`方法中，在使用`BitmapFactory`类检索位图后，调用`onRotateCaptureImageIfNeeded`方法，并将位图作为参数传递：

```kt
bitmap = rotateCapturedImageIfNeeded(bitmap);

```

1.  如果再次运行应用程序，您会发现在纵向模式下一切都很好：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_06_07.jpg)

这些东西很容易实现，并且会提高您的应用程序的质量，尽管有时它们也会让您感到困惑，让您想知道为什么一个解决方案不能在任何设备上都正常工作。现在一切看起来都很好，但在平板电脑或华为、LG 或 HTC 设备上会是什么样子呢？没有什么是不能解决的，但由于您没有一堆 Android 设备（或者也许您有），测试是困难的。

尽可能在尽可能多的设备上测试您的应用程序总是一件好事。考虑使用远程测试服务，例如 TestDroid。您可以在[www.testdroid.com](http://www.testdroid.com)找到他们的网站。在第八章中，将讨论这些和其他主题，但首先我们将在即将到来的章节中看一下可观察对象和内容提供程序。

## 还有更多...

拍摄视频更有趣。还有一个用于视频捕获的 Camera2 API 示例可用。您也可以通过**导入示例**选项来检查示例项目。

## 另请参阅

+   第八章, *提高质量*


# 第七章：内容提供程序和观察者

在大多数应用程序中，我们需要持久化数据，并经常使用 SQLite 来实现这一目的。

非常常见的情况是列表和详细视图。通过使用内容提供程序，我们不仅提供了应用程序之间的通信方式，还在我们自己的应用程序中节省了大量工作。

在本章中，您将学习：

+   内容提供程序

+   使用内容提供程序消耗和更新数据

+   将投影更改为在您的应用程序中显示**关键绩效指标**（**KPIs**）

+   使用内容提供程序与其他应用程序进行通信

# 介绍

如果我们想要创建一个新的行，或者想要编辑数据库中的一行，应用程序将显示包含详细信息的片段或活动，用户可以在那里输入或修改一些文本和其他值。一旦记录被插入或更新，列表需要知道这些变化。告诉列表活动或片段有关这些变化并不难做到，但有一种更优雅的方法可以实现这一点。为此，以及其他我们将在以后了解的原因，我们将研究内容提供程序的内容。

Android 内容提供程序框架允许我们为应用程序创建更好的设计。其中一个特点是它允许我们注意到某些数据已经发生了变化。即使在不同的应用程序之间也可以工作。

# 内容提供程序

构建内容提供程序是一件非常聪明的事情。内容提供程序 API 具有一个有趣的功能，允许应用程序观察数据集的变化。

内容提供程序将一个进程中的数据与另一个进程中运行的代码连接起来，甚至可以在两个完全不同的应用程序之间进行连接。如果您曾经编写过从 Gallery 应用中选择图像的代码，您可能已经经历过这种行为。某些组件操作其他组件依赖的持久数据集。内容提供程序可以使用许多不同的方式来存储数据，可以存储在数据库中，文件中，甚至可以通过网络进行存储。

数据集由唯一的 URI 标识，因此可以要求在某个 URI 发生变化时进行通知。这就是观察者模式的应用之处。

观察者模式是一种常见的软件设计模式，其中一个对象（主题）具有一个或多个依赖对象（观察者，也称为监听器），它们将自动被通知任何状态更改。

## 还有更多...

### 设计模式

要了解更多关于这个和其他**面向对象**（**OO**）设计模式，您可以查看[`www.oodesign.com/observer-pattern.html`](http://www.oodesign.com/observer-pattern.html)。

### RxJava

RxJava 是一个非常有趣的库，也可以在 Android 版本中使用。响应式编程与观察者模式有主要相似之处。响应式代码的基本构建块也是可观察对象和订阅者。

要了解更多关于 Rx 和 RxJava，您可以访问这些网站：

+   [`github.com/reactivex/rxandroid`](https://github.com/reactivex/rxandroid)

+   [`github.com/ReactiveX/RxJava/wiki/How-To-Use-RxJava`](https://github.com/ReactiveX/RxJava/wiki/How-To-Use-RxJava)

+   [`blog.danlew.net/2014/09/15/grokking-rxjava-part-1/`](http://blog.danlew.net/2014/09/15/grokking-rxjava-part-1/)

## 另请参阅

+   第八章 ，*提高质量*

# 使用内容提供程序消耗和更新数据 - 每日想法

为了演示如何创建和使用内容提供程序，我们将创建一个应用程序，用于存储您每天的想法和快乐程度。

是的，有一些应用程序正在这样做；但是，如果您想创建一个应用程序来记录体育笔记和分数，可以随意修改代码，因为它基本上涉及相同的功能。

在这个示例中，我们将使用内容提供程序存储新的想法并检索它们。对于应用程序的各个元素，我们将使用片段，因为它们将清楚地展示观察者模式的效果。

## 准备工作

对于这个配方，您只需要运行 Android Studio 并拥有一个物理或虚拟的 Android 设备。

## 如何做...

让我们看看如何使用内容提供程序设置项目。我们将使用导航抽屉模板：

1.  在 Android Studio 中创建一个名为`DailyThoughts`的新项目。点击**下一步**按钮。

1.  选择**手机和平板电脑**选项，然后点击**下一步**按钮。

1.  选择**导航抽屉活动**，然后点击**下一步**按钮。

1.  接受**自定义活动**页面上的所有值，然后点击**完成**按钮。

1.  打开`res/values`文件夹中的`strings.xml`文件。修改以`title_section`开头的条目的字符串。用我们应用程序所需的菜单项替换它们。还替换`action_sample`字符串：

```kt
<string name="title_section_daily_notes">Daily  
 thoughts</string><string name="title_section_note_list">Thoughts 
 list</string>
<string name="action_add">Add thought</string>
```

1.  打开`NavigationDrawerFragment`文件，在`onCreate`方法中，相应地修改适配器的字符串：

```kt
mDrawerListView.setAdapter(new ArrayAdapter<String>(
        getActionBar().getThemedContext(),
        android.R.layout.simple_list_item_activated_1,
        android.R.id.text1,
        new String[]{
                getString(R.string.title_section_daily_notes),
                getString(R.string.title_section_note_list)
        }));
```

1.  在同一个类中，在`onOptionsItemSelected`方法中，删除显示 toast 的第二个`if`语句。我们不需要它。

1.  从`res/menu`文件夹中打开`main.xml`。删除设置项，并修改第一项，使其使用`action_add`字符串。还重命名它的 ID 并为其添加一个漂亮的图标：

```kt
<menu xmlns:android= 
 "http://schemas.android.com/apk/res/android"  
   tools:context=".MainActivity">
<item android:id="@+id/action_add"  
 android:title="@string/action_add"android:icon="@android:drawable/ic_input_add"android:showAsAction="withText|ifRoom" />
</menu>
```

1.  在`MainActivity`文件中，在`onSectionAttached`部分，为不同的选项应用正确的字符串：

```kt
public void onSectionAttached(int number) {
    switch (number) {
        case 0:
            mTitle = getString(  
             R.string.title_section_daily_notes);
            break;
        case 1:
            mTitle = getString( 
             R.string.title_section_note_list);
             break;
    }
}
```

1.  创建一个名为`db`的新包。在这个包中，创建一个名为`DatabaseHelper`的新类，它继承`SQLiteOpenHelper`类。它将帮助我们为我们的应用程序创建一个新的数据库。它将只包含一个表：`thoughts`。每个`Thought table`将有一个 id，一个名称和一个幸福评分：

```kt
public class DatabaseHelper extends SQLiteOpenHelper {
    public static final String DATABASE_NAME = 
     "DAILY_THOUGHTS";
    public static final String THOUGHTS_TABLE_NAME =   
     "thoughts";
    static final int DATABASE_VERSION = 1;
    static final String CREATE_DB_TABLE =
      " CREATE TABLE " + THOUGHTS_TABLE_NAME +
      " (_id INTEGER PRIMARY KEY AUTOINCREMENT, " +" name TEXT NOT NULL, " +" happiness INT NOT NULL);";public DatabaseHelper(Context context){
        super(context, DATABASE_NAME, null, 
         DATABASE_VERSION);}
    @Override
    public void onCreate(SQLiteDatabase db)
    {
        db.execSQL(CREATE_DB_TABLE);
    }
    @Override 
	 public void onUpgrade(SQLiteDatabase db, int 
     oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " +  
         THOUGHTS_TABLE_NAME);
        onCreate(db);}
}
```

1.  创建另一个包并命名为`providers`。在这个包中，创建一个名为`ThoughtsProvider`的新类。这将是我们所有日常想法的内容提供程序。将其作为`ContentProvider`类的后代。

1.  从**代码**菜单中，选择**实现方法**选项。在出现的对话框中，所有可用的方法都被选中。接受这个建议，然后点击**确定**按钮。您的新类将扩展这些方法。

1.  在类的顶部，我们将创建一些静态变量：

```kt
static final String PROVIDER_NAME =  
 "com.packt.dailythoughts";
static final String URL = "content://" + PROVIDER_NAME +  
 "/thoughts";
public static final Uri CONTENT_URI = Uri.parse(URL);
public static final String THOUGHTS_ID = "_id";
public static final String THOUGHTS_NAME = "name";
public static final String THOUGHTS_HAPPINESS = 
 "happiness";
static final int THOUGHTS = 1;
static final int THOUGHT_ID = 2;
static final UriMatcher uriMatcher;
static{
    uriMatcher = new UriMatcher(UriMatcher.NO_MATCH);
    uriMatcher.addURI(PROVIDER_NAME, "thoughts", 
     THOUGHTS);
    uriMatcher.addURI(PROVIDER_NAME, "thoughts/#",   
     THOUGHT_ID);
}
```

1.  添加一个私有成员`db`，引用`SQLiteDatabase`类，并修改`onCreate`方法。我们创建一个新的数据库助手：

```kt
private SQLiteDatabase db;
@Override 
   public boolean onCreate() {
    Context context = getContext();
    DatabaseHelper dbHelper = new DatabaseHelper(context);
    db = dbHelper.getWritableDatabase();
    return (db == null)? false:true;
}
```

### 查询

接下来，实现`query`方法。查询返回一个游标对象。游标表示查询的结果，并指向查询结果中的一个，因此结果可以被高效地缓冲，因为它不需要将数据加载到内存中：

```kt
private static HashMap<String, String> 
 THOUGHTS_PROJECTION; 
@Override 
public Cursor query(Uri uri, String[] projection, 
 String selection, String[] selectionArgs, String 
  sortOrder) {
   SQLiteQueryBuilder builder = new SQLiteQueryBuilder();
   builder.setTables( 
    DatabaseHelper.THOUGHTS_TABLE_NAME);
   switch (uriMatcher.match(uri)) {
      case THOUGHTS:
        builder.setProjectionMap(
         THOUGHTS_PROJECTION);
         break;
      case THOUGHT_ID:
        builder.appendWhere( THOUGHTS_ID + "=" + uri.getPathSegments().get(1));
        break;
      default:
        throw new IllegalArgumentException(
         "Unknown URI: " + uri);
    }
    if (sortOrder == null || sortOrder == ""){
        sortOrder = THOUGHTS_NAME;
    }
    Cursor c = builder.query(db, projection,selection, selectionArgs,null, null, sortOrder);
    c.setNotificationUri(    
     getContext().getContentResolver(), uri);
    return c;
}
```

### 注意

`setNotificationUri`调用注册指令以监视内容 URI 的更改。

我们将使用以下步骤实现其他方法：

1.  实现`getType`方法。`dir`目录表示我们想要获取所有的想法记录。`item`术语表示我们正在寻找特定的想法：

```kt
@Override 
public String getType(Uri uri) {
    switch (uriMatcher.match(uri)){
      case THOUGHTS:
        return "vnd.android.cursor.dir/vnd.df.thoughts";
     case THOUGHT_ID:
       return "vnd.android.cursor.item/vnd.df.thoughts";
     default:
       throw new IllegalArgumentException(
        "Unsupported URI: " + uri);
    }
}
```

1.  实现`insert`方法。它将基于提供的值创建一个新记录，如果成功，我们将收到通知：

```kt
@Override
public Uri insert(Uri uri, ContentValues values) {
   long rowID = db.insert(  
    DatabaseHelper.THOUGHTS_TABLE_NAME , "", values);
   if (rowID > 0)
   {
      Uri _uri = ContentUris.withAppendedId(CONTENT_URI, 
       rowID);
      getContext().getContentResolver().notifyChange( _uri, 
       null);
      return _uri;
    }
    throw new SQLException("Failed to add record: " + uri);
}
```

1.  `delete`和`update`方法超出了本配方的范围，所以我们现在不会实现它们。挑战：在这里添加您自己的实现。

1.  打开`AndroidManifest.xml`文件，并在`application`标签内添加`provider`标签：

```kt
<providerandroid:name=".providers.ThoughtsProvider"android:authorities="com.packt.dailythoughts"android:readPermission=  
     "com.packt.dailythoughts.READ_DATABASE"android:exported="true" />
```

### 注意

出于安全原因，在大多数情况下，您应该将导出属性的值设置为`false`。我们将此属性的值设置为`true`的原因是，稍后我们将创建另一个应用程序，该应用程序将能够从此应用程序中读取内容。

1.  添加其他应用程序读取数据的权限。我们将在最后一个配方中使用它。将其添加到`application`标签之外：

```kt
<permission   
 android:name="com.packt.dailythoughts.READ_DATABASE"android:protectionLevel="normal"/>
```

1.  打开`strings.xml`文件并向其中添加新的字符串：

```kt
<string name="my_thoughts">My thoughts</string>
<string name="save">Save</string>
<string name="average_happiness">Average 
  happiness</string>
```

1.  创建两个新的布局文件：`fragment_thoughts.xml`用于我们的想法列表和`fragment_thoughts_detail`用于输入新的想法。

1.  为`fragment_thoughts.xml`定义布局。 一个`ListView`小部件很适合显示所有的想法：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android= 
 "http://schemas.android.com/apk/res/android"
   android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical" >
    <ListView
        android:id="@+id/thoughts_list"android:layout_width="match_parent"android:layout_height="wrap_content" ></ListView>
</LinearLayout> 
```

1.  `fragment_thoughts_detail.xml`的布局将包含`EditText`和`RatingBar`小部件，以便我们可以输入我们的想法和我们当前的幸福程度：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android=
  "http://schemas.android.com/apk/res/android"android:orientation="vertical"android:layout_gravity="center"android:layout_margin="32dp"android:padding="16dp"android:layout_width="match_parent"android:background="@android:color/holo_green_light"android:layout_height="wrap_content">
    <TextView
        android:layout_margin="8dp"android:textSize="16sp"android:text="@string/my_thoughts"
     android:layout_width="match_parent"android:layout_height="wrap_content" />
    <EditText
        android:id="@+id/thoughts_edit_thoughts"android:layout_margin="8dp"android:layout_width="match_parent"android:layout_height="wrap_content" />
    <RatingBar
        android:id="@+id/thoughs_rating_bar_happy"android:layout_width="wrap_content"android:layout_height="wrap_content"android:layout_gravity="center_horizontal"android:clickable="true"android:numStars="5"android:rating="0" />
    <Button
        android:id="@+id/thoughts_detail_button"android:text="@string/save"          
        android:layout_width="match_parent"android:layout_height="wrap_content" />
</LinearLayout>
```

1.  还要为想法列表中的行创建布局。将其命名为`adapter_thought.xml`。添加文本视图以显示 ID、标题或名称和评分：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android=
  "http://schemas.android.com/apk/res/android"
    android:orientation="vertical"
    android:layout_gravity="center"
    android:layout_margin="32dp"
    android:padding="16dp"
    android:layout_width="match_parent"
    android:background=
     "@android:color/holo_green_light"
    android:layout_height="wrap_content">
    <TextView
        android:layout_margin="8dp"
        android:textSize="16sp"
        android:text="@string/my_thoughts"
     android:layout_width="match_parent"
  android:layout_height="wrap_content" />
    <EditText
        android:id="@+id/thoughts_edit_thoughts"
        android:layout_margin="8dp"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
    <RatingBar
        android:id="@+id/thoughs_rating_bar_happy"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="center_horizontal"
        android:clickable="true"
        android:numStars="5"
        android:rating="0" />
    <Button
        android:id="@+id/thoughts_detail_button"
        android:text="@string/save"          
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
</LinearLayout>

```

1.  创建一个新的包，命名为：`fragments`，并向其中添加两个新的类：`ThoughtsDetailFragment`和`ThoughtsFragment`，它们都将是`Fragment`类的子类。

1.  在`ThoughtsFragment`类中，添加`LoaderCallBack`的实现：

```kt
public class ThoughtsFragment extends Fragment   
  implementsLoaderManager.LoaderCallbacks<Cursor>{
```

1.  从**代码**菜单中选择**实现方法**，接受建议的方法，并单击**确定**按钮。它将创建`onCreateLoader`，`onLoadFinished`和`onLoaderReset`的实现。

1.  添加两个私有成员，它们将保存列表视图和适配器：

```kt
private ListView mListView;private SimpleCursorAdapter mAdapter;
```

1.  重写`onCreateView`方法，在其中我们将填充布局并获取对列表视图的引用。从这里，我们还将调用`getData`方法：

```kt
@Override
public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
    final View view = inflater.inflate( 
     R.layout.fragment_thoughts, container, false);
    mListView = (ListView)view.findViewById( 
     R.id.thoughts_list);
    getData();
    return view;
}
```

### 加载程序管理器

以下步骤将帮助我们向应用程序添加加载程序管理器：

1.  实现`getData`方法。我们将使用`loaderManager`的`initLoader`方法。投影定义了我们想要检索的字段，目标是`adapter_thought_title`布局中的 ID 数组，这将节省我们使用`SimpleCursorAdapter`类的一些工作。

```kt
private void getData(){String[] projection = new String[] { 
     ThoughtsProvider.THOUGHTS_ID,   
     ThoughtsProvider.THOUGHTS_NAME, 
     ThoughtsProvider.THOUGHTS_HAPPINESS};
    int[] target = new int[] {    
     R.id.adapter_thought_id,  
     R.id.adapter_thought_title,  
     R.id.adapter_thought_rating };
    getLoaderManager().initLoader(0, null, this);
    mAdapter = new SimpleCursorAdapter(getActivity(),   
     R.layout.adapter_thought, null, projection,  
      target, 0);
    mListView.setAdapter(mAdapter); 
}
```

1.  在`initLoader`调用之后，需要创建一个新的加载程序。为此，我们将不得不实现`onLoadFinished`方法。我们将使用与适配器相同的投影，并使用我们在前面步骤中创建的`ThoughtsProvider`的`uri`内容创建`CursorLoader`类。我们将按 ID（降序）对结果进行排序：

```kt
@Override
public Loader<Cursor> onCreateLoader(int id, Bundle args) {
        String[] projection = new String[] { 
     ThoughtsProvider.THOUGHTS_ID,   
     ThoughtsProvider.THOUGHTS_NAME, 
     ThoughtsProvider.THOUGHTS_HAPPINESS};
    String sortBy = "_id DESC";CursorLoader cursorLoader = new 
    CursorLoader(getActivity(), 
    ThoughtsProvider.CONTENT_URI, projection, null, 
     null, sortBy);
    return cursorLoader;
}
```

1.  在`onLoadFinished`中，通知适配器加载了数据：

```kt
mAdapter.swapCursor(data);
```

1.  最后，让我们为`onLoaderReset`方法添加实现。在这种情况下，数据不再可用，因此我们可以删除引用。

```kt
mAdapter.swapCursor(null);
```

1.  让我们来看看`ThoughtsDetailFragment`方法。重写`onCreateView`方法，填充布局，并为布局中的保存按钮添加点击监听器：

```kt
@Override
public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
    final View view = inflater.inflate( 
     R.layout.fragment_thoughts_detail, container,  
      false); 
   view.findViewById( 
    R.id.thoughts_detail_button).setOnClickListener( 
     new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            addThought();
        }
    });
    return view;
}
```

1.  添加`addThought`方法。我们将根据通过`EditText`和`RatingBar`字段输入创建新的内容值。我们将根据提供的 URI 使用内容解析器的`insert`方法。插入新记录后，我们将清除输入：

```kt
private void addThought(){
    EditText thoughtsEdit = 
     (EditText)getView().findViewById(    
      R.id.thoughts_edit_thoughts);
    RatingBar happinessRatingBar =            
     (RatingBar)getView().findViewById(
      R.id.thoughs_rating_bar_happy);
    ContentValues values = new ContentValues();
    values.put(ThoughtsProvider.THOUGHTS_NAME, 
     thoughtsEdit.getText().toString());
    values.put(ThoughtsProvider.THOUGHTS_HAPPINESS,    
     happinessRatingBar.getRating());
    getActivity().getContentResolver().insert( 
     ThoughtsProvider.CONTENT_URI, values);
    thoughtsEdit.setText("");
    happinessRatingBar.setRating(0);
}
```

1.  再次是将事物粘合在一起的时候了。打开`MainActivity`类，并添加两个私有成员，它们将引用我们创建的片段，如下所示：

```kt
private ThoughtsFragment mThoughtsFragment;
private ThoughtsDetailFragment mThoughtsDetailFragment;
```

1.  添加两个私有成员，如果需要，将它们初始化，并返回实例：

```kt
private ThoughtsFragment getThoughtsFragment(){
    if (mThoughtsFragment==null) {
        mThoughtsFragment = new ThoughtsFragment();
    }
    return mThoughtsFragment;
}
private ThoughtsDetailFragment 
getThoughtDetailFragment() {
   if (mThoughtsDetailFragment==null){
    mThoughtsDetailFragment = new ThoughtsDetailFragment();
    }
    return mThoughtsDetailFragment;
}
```

1.  删除`onNavigationDrawerItemSelected`的实现，并添加一个新的来显示想法列表。我们稍后将实现 KPI 选项：

```kt
@Override
  public void onNavigationDrawerItemSelected(int  
  position) {
   FragmentManager fragmentManager =    
    getFragmentManager();
   if (position==1) {
        fragmentManager.beginTransaction().   
         replace(R.id.container, 
          getThoughtsFragment()).commit();
    }
}
```

1.  在`onOptionsItemSelected`方法中，测试 id 是否为`action_add`，如果是，则显示详细片段。在获取 id 的行后立即添加实现：

```kt
if (id== R.id.action_add){FragmentManager fragmentManager = 
     getFragmentManager();
    fragmentManager.beginTransaction().add( 
     R.id.container, getThoughtDetailFragment()  
      ).commit();
}
```

### 注意

这里使用`add`而不是`replace`。我们希望详细片段出现在堆栈的顶部。

1.  保存详细信息后，片段必须再次被移除。再次打开`ThoughtsDetailFragment`。在`addThought`方法的末尾，添加以下内容以完成操作：

```kt
getActivity().getFragmentManager().beginTransaction().
 remove(this).commit();
```

1.  然而，最好让活动处理片段的显示，因为它们旨在成为活动的辅助程序。相反，我们将为`onSave`事件创建一个监听器。在类的顶部，添加一个`DetailFragmentListener`接口。还创建一个私有成员和一个 setter：

```kt
public interface DetailFragmentListener {
    void onSave();
}
private DetailFragmentListener 
 mDetailFragmentListener; 
public void setDetailFragmentListener(  
 DetailFragmentListener listener){
    mDetailFragmentListener = listener;
}
```

1.  在`addThought`成员的末尾添加这些行，以便让监听器知道已保存事物：

```kt
if (mDetailFragmentListener != null){
    mDetailFragmentListener.onSave();
}
```

1.  返回`MainActivity`类，并为其添加一个监听器实现。如果需要，您可以使用**代码**菜单中的**实现方法**选项：

```kt
public class MainActivity extends Activityimplements NavigationDrawerFragment. 
   NavigationDrawerCallbacks, 
    ThoughtsDetailFragment.DetailFragmentListener {
@Override 
 public void onSave() {      
  getFragmentManager().beginTransaction().remove(
   mThoughtsDetailFragment).commit();
}
```

1.  要告诉详细片段主活动正在监听，请滚动到`getThoughtDetailFragment`类并在创建新详细片段后立即调用`setListener`方法：

```kt
mThoughtsDetailFragment.setDetailFragmentListener(this);
```

现在运行应用程序，从导航抽屉中选择**Thoughts list**，然后单击加号添加新的想法。以下截图显示了添加想法的示例：

![加载程序管理器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_07_01.jpg)

我们不需要告诉包含列表的片段有关我们在详细片段中创建的新想法。使用具有观察者的内容提供程序，列表将自动更新。

这样我们就可以完成更多，写更少容易出错的功能，从而写更少的代码，这正是我们想要的。它使我们能够提高代码的质量。

## 另请参阅

+   参见第五章, *大小很重要*

+   参见第八章, *提高质量*

# 更改投影以在应用程序中显示 KPI

我们可以使用不同的投影和相同的观察者模式来显示一些 KPI。实际上，这很容易，正如我们将在本示例中看到的那样。

## 准备工作

对于这个示例，您需要成功完成上一个示例。

## 如何做...

我们将继续在上一个示例中的应用程序上工作，并添加一个新视图来显示 KPI：

1.  打开您在上一个示例中工作的项目。

1.  添加一个新的布局，`fragment_thoughts_kpi.xml`：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android=  
 "http://schemas.android.com/apk/res/android"
  android:orientation="vertical"   
  android:layout_width="match_parent"
  android:gravity="center_horizontal"   
  android:padding="16dp"
  android:layout_height="match_parent">
  <TextView
        android:id="@+id/thoughts_kpi_count"          
        android:textSize="32sp"
        android:layout_margin="16dp"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />
    <TextView
        android:id="@+id/thoughts_kpi_avg_happiness"
        android:text= "@string/average_happiness"
        android:textSize="32sp"
        android:layout_margin="16dp"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />
    <RatingBar
        android:id="@+id/thoughts_rating_bar_happy"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="center_horizontal"
        android:clickable="false"
        android:numStars="5"
        android:rating="0" />
</LinearLayout>

```

1.  添加一个新的片段并命名为`ThoughtsKpiFragment`。它是从`Fragment`类继承的。我们将在这里使用`LoaderManager`，所以它基本上看起来像这样：

```kt
public class ThoughtsKpiFragment extends Fragment    
 implements LoaderManager.LoaderCallbacks<Cursor> {
   @Override
    public Loader<Cursor> onCreateLoader(int id, Bundle args) {return null;
    }
    @Override
	public void onLoadFinished(Loader<Cursor> loader, Cursordata) {
    }
    @Override
    public void onLoaderReset(Loader<Cursor> loader) {
    }
}
```

1.  因为我们将使用两个加载程序来显示两个不同的 KPI，所以我们首先要添加两个常量值：

```kt
public static int LOADER_COUNT_THOUGHTS = 1;
public static int LOADER_AVG_RATING = 2;
```

1.  覆盖`onCreate`方法：

```kt
@Override
public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
    final View view = inflater.inflate( 
     R.layout.fragment_thoughts_kpi, container, false);
    getKpis();
    return view;
}
```

1.  创建`getKpis`方法（在这里我们为不同目的两次初始化加载程序）：

```kt
private void getKpis(){
    getLoaderManager().initLoader(LOADER_COUNT_THOUGHTS, null, 
     this);
    getLoaderManager().initLoader(LOADER_AVG_RATING, null, 
     this); 
}
```

1.  添加`onCreateLoader`方法的实现。这次投影取决于加载程序的 ID。投影就像您期望的那样，如果它是普通的 SQL。我们正在计算行数，并计算平均幸福指数：

```kt
@Override 
 public Loader<Cursor> onCreateLoader(int id, Bundle args) {
    if (id == LOADER_COUNT_THOUGHTS) {
      String[] projection = new String[] {"COUNT(*) AS kpi"};
      android.content.CursorLoader cursorLoader = new android.content.CursorLoader(getActivity(),  
        ThoughtsProvider.CONTENT_URI, projection, null, null, 
         null);
      return cursorLoader;
    }
    else {
      String[] projection = new String[]
         {"AVG(happiness) AS kpi"};
      android.content.CursorLoader cursorLoader = new 
      android.content.CursorLoader(getActivity(), 
       ThoughtsProvider.CONTENT_URI, projection, null, null, 
        null);
      return cursorLoader;}
}
```

1.  一旦数据到达，我们将到达`onLoadFinished`方法，并调用方法显示数据（如果有的话）：

```kt
@Override
public void onLoadFinished(Loader<Cursor> loader, Cursor data) {
    if (data == null || !data.moveToNext()) {
        return;
    }
    if (loader.getId() == LOADER_COUNT_THOUGHTS) {
        setCountedThoughts(data.getInt(0)); 
    }
    else{
        setAvgHappiness(data.getFloat(0));
    }
}
```

1.  添加`setCountedThoughts`和`setAvgHappiness`方法。如果片段仍附加到活动中，我们将更新文本视图或评分栏：

```kt
private void setCountedThoughts(final int counted){
    if (getActivity()==null){
        return;
    }
    getActivity().runOnUiThread(new Runnable() {
        @Override
        public void run() {
          TextView countText = (TextView)getView().findViewById(
             R.id.thoughts_kpi_count);
          countText.setText(String.valueOf(counted));
        }
    });
}
private void setAvgHappiness(final float avg){
    if (getActivity()==null){
        return;
    }
    getActivity().runOnUiThread(new Runnable() {
        @Override
		public void run() {
            RatingBar ratingBar =        
             (RatingBar)getView().findViewById(
              R.id.thoughts_rating_bar_happy);
            ratingBar.setRating(avg);}
    });
}
```

1.  在`MainActivity`文件中，添加一个 KPI 片段的私有成员：

```kt
private ThoughtsKpiFragment mThoughtsKpiFragment;
```

1.  创建一个`getKpiFragment`方法：

```kt
private ThoughtsKpiFragment getKpiFragment(){
    if (mThoughtsKpiFragment==null){
        mThoughtsKpiFragment = new ThoughtsKpiFragment();
    }
    return mThoughtsKpiFragment;
}
```

1.  找到`onNavigationDraweItemSelected`方法，并将其添加到`if`语句中：

```kt
… 
else if (position==0){ 
    fragmentManager.beginTransaction()
            .replace(R.id.container, getKpiFragment())
            .commit();
}
```

运行您的应用程序。现在我们的想法应用程序中有一些整洁的统计数据：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_07_02.jpg)

在这个和上一个示例中，我们已经看到了一旦掌握了内容提供程序的概念，处理数据变得多么容易。

到目前为止，我们在同一个应用程序中完成了所有这些工作；然而，由于我们已经准备好导出内容提供程序，让我们找出如何在不同的应用程序中读取我们的想法。现在就让我们来做吧。

## 另请参阅

参见第五章, *大小很重要*

参见第八章, *提高质量*

# 使用内容提供程序与其他应用程序通信

如果您阅读谷歌关于内容提供程序的文档，您会注意到内容提供程序基本上是为了在请求时向其他应用程序提供数据。这些请求由`ContentResolver`类的方法处理。

我们将创建一个新的应用程序，它将从另一个应用程序中读取我们的日常想法。

## 准备工作

对于这个示例，您需要成功完成上一个示例。确保您也向应用程序添加了一些想法，否则将没有东西可读，正如显而易见的船长所告诉我们的那样。

## 如何做...

首先我们将创建一个新的应用程序。它将读取我们的想法。这是肯定的！

1.  在 Android Studio 中创建一个新项目，命名为`DailyAnalytics`，然后点击**确定**按钮。

1.  选择**手机和平板电脑**，然后点击**下一步**按钮。

1.  选择**空白活动**，然后点击**下一步**按钮。

1.  接受**自定义活动**视图中的所有值，然后点击**完成**按钮。

1.  打开`AndroidManifest.xml`文件，并添加与`DailyThought`应用程序通信所需的权限：

```kt
<uses-permission android:name=  
 "com.packt.dailythoughts.READ_DATABASE"/>
```

1.  打开`activity_main.xml`布局，并将`TextView`应用程序的`id`更改为`main_kpi_count`：

```kt
<TextView
    android:id="@+id/main_kpi_count"android:text="@string/hello_world"  
    android:layout_width="wrap_content"android:layout_height="wrap_content" />
```

1.  在`MainActivity`类中，添加`LoaderCallBack`实现：

```kt
public class MainActivity extends Activity  implementsLoaderManager.LoaderCallbacks<Cursor>
```

1.  在`onCreate`方法的末尾调用`initLoader`：

```kt
getLoaderManager().initLoader(0, null, this);
```

1.  为`onCreateLoader`方法添加一个实现。它的工作方式基本与应用程序的内容提供程序相同：

```kt
@Override
public Loader<Cursor> onCreateLoader(int id, Bundle args) {
    Uri uri = Uri.parse(  
     "content://com.packt.dailythoughts/thoughts");
    String[] projection = new String[] { "_id", "name", 
     "happiness"};
    String sortBy = "name";
    CursorLoader cursorLoader = new  
    android.content.CursorLoader(
     this,uri, projection, null, null, null);
    return cursorLoader;
}
```

1.  在`onLoadFinished`方法中，我们可以根据您在其他应用程序中输入的内容显示一些分析：

```kt
@Override
public void onLoadFinished(Loader<Cursor> loader, 
 Cursor data) {
   final StringBuilder builder = new StringBuilder();
    builder.append(
     "I know what you are thinking of... \n\n");
   while ( (data.moveToNext())){
       String onYourMind = data.getString(1);
       builder.append("You think of "+
         onYourMind+". ");
       if (data.getInt(2) <= 2){
           builder.append(
            "You are sad about this...");
        }
        if (data.getInt(2) >= 4) {
           builder.append("That makes you happy!");
        }
        builder.append("\n");
    }
    builder.append("\n Well, am I close? ;-)");
    runOnUiThread(new Runnable() {
        @Override
		public void run() {TextView countText = (TextView) 
           findViewById(R.id.main_kpi_count);
          countText.setText(String.valueOf(
           builder.toString()));}});}
```

运行应用程序，看到所有你的想法出现在这里，如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_07_03.jpg)

可怕，不是吗？使用内容提供程序，很容易在不同的应用程序之间共享数据。这就是许多应用程序如联系人或画廊的工作方式。

## 还有更多...

我们已经学习了内容提供程序的工作原理，并且已经偷偷看了一眼观察者模式。使用这个和其他模式可以提高我们应用程序的质量。

现在事情将变得非常严肃。避免潜在错误，减少需要编写的代码量，并使其在任何 Android 设备上运行！我们将在下一章中找出如何做到这一点。

## 另请参阅

+   参考第八章, *提高质量*
