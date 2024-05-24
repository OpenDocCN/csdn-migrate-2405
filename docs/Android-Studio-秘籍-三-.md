# Android Studio 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/4884403F3172F01088859FB8C5497CF5`](https://zh.annas-archive.org/md5/4884403F3172F01088859FB8C5497CF5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：提高质量

您刚刚完成了应用的编码。现在呢？尽快将其放到 Play 商店上！

不要等待，您还没有完成！您是否正确测试了您的应用？它是否适用于任何 Android 版本？在任何设备上？在任何情况下？

在本章中，我们将重点关注：

+   模式和支持注释

+   使用 Robolectrics 进行单元测试

+   代码分析

# 介绍

有一些常见的陷阱要避免，以及一些模式，您可能希望应用以提高应用程序的质量。您已经在之前的章节中看到了其中一些。此外，还有一些有趣的工具可以用来测试和分析您的代码。

在接下来的路线图中，您会注意到在将应用上线之前，您需要完成不同的阶段：

![介绍](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_08_01.jpg)

您的代码结构、健壮性、可维护性以及其与功能要求的符合程度是关键因素。

功能质量通过软件测试来衡量，因此我们需要将应用分发给我们的测试人员。我们将在第十章中讨论这一点，*测试您的应用程序*。

通过运行单元测试和手动代码检查（同行审查）或使用诸如 Android Lint 之类的工具来评估结构质量，您将在本章的最后一个配方中了解更多有关它。现在的问题是代码架构是否满足良好软件工程的要求？

总的来说，有一些有趣的原则将帮助您提高代码的质量。其中一些列在这里：

+   学习活动生命周期，并以正确的方式使用片段。

+   如果可以避免，就不要分配内存。

+   避免过于沉重的片段和活动。

+   考虑**模型视图控制器**（**MVC**）方法。应用正确的模式。

+   在一个地方解决一次问题。**不要重复自己**（**DRY**）。

+   不要做不需要做的工作（尚未）。也被称为：**你不会需要它**（**YAGNI**）。

下一个配方将让您了解模式是什么，以及为什么您会想要应用它们。

# 模式和支持注释

质量是一项严肃的业务，因此我们将把它与一些乐趣结合起来。在即将到来的配方中，我们将创建一个测验应用。我们将使用 Google Play 服务进行此操作，并且我们将研究可以应用于我们的应用的模式，特别是 MVC 和**模型视图控制器**（**MVP**）方法。

那么设计模式实际上是什么？设计模式是常见问题的解决方案。我们可以在任何地方重用这样的模式。没有必要重新发明轮子（除非您当然可以想到更好的轮子），也没有必要重复自己。

模式是我们可以信任的最佳实践。它们可以帮助我们加快开发过程，包括测试。

一些模式包括：

+   MVC

+   MVP

+   可观察的

+   工厂

+   单例

+   支持注释

+   Google Play 服务

## MVC

MVC 最适合较大的项目。这种模式的好处是关注点的分离。我们可以将 UI 代码与业务逻辑分开。控制器将负责显示哪个视图。它将从另一层获取数据，一个类似存储库的类，该类将从某处获取其数据，并通过模型（或模型列表）将数据传递给 UI。控制器不知道数据来自何处以及如何显示。这些是存储库类和 UI 的任务，分别。

## MVP

在大多数情况下，MVP 是与 Android 应用程序开发一起使用的更合适的模式，因为活动和片段的性质。使用 MVP 模式，一个 Presenter 包含视图的 UI 逻辑。视图的所有调用都直接委托给它。Presenter 将通过接口与视图通信，允许我们稍后使用模拟数据创建单元测试。

## 观察者模式

我们在第七章中已经看到了这种模式，*内容提供者和观察者*。观察者观察另一个对象的变化。

## 工厂模式

这种模式有助于创建对象。我们之前使用过的位图工厂（并且我们将在本教程中再次使用）是工厂模式的一个很好的例子。

## 单例

单例模式将防止我们拥有对象的多个实例。通常，它是一个（类）方法，返回一个实例。如果它不存在，它将被创建，否则它将返回先前创建的实例。应用程序类就是单例模式的一个例子。

## 支持注释

支持注释可以帮助我们向代码检查工具（如 lint）提供提示。它们可以帮助您通过添加元数据标签并运行代码检查来检测问题，例如空指针异常和资源类型冲突。支持库本身已经用这些注释进行了注释。是的，他们自己也在使用注释，这证明使用注释是正确的方法。

基本上有三种我们可以使用的注释类型：空值注释、资源类型注释和 IntDef \ StringDef 注释。例如，我们可以使用`@NonNull`注释来指示给定参数不能为空，或者我们可以使用`@Nullable`注释来指示返回值可以为空。

## Google Play 服务

Play Games SDK 提供跨平台的 Google Play 游戏服务，让您可以轻松地在平板电脑和移动设备游戏中集成流行的游戏功能，例如成就、排行榜、保存的游戏和实时多人游戏（在 Android 上）选项。

现在理论已经足够了！让我们创建我们的测验应用程序，并应用我们在这里讨论过的一些理论。

## 准备工作

对于本教程，您需要拥有最新版本的 Android Studio 和已安装 Google Play 服务的真实设备，这对大多数设备来说都是成立的。或者，您可以在虚拟 Genymotion 设备上安装它们，但这将需要一些额外的准备工作。

此外，您需要拥有（或创建）一个 Google 开发者帐户。

## 如何做...

然后开始。启动 Android Studio 并执行以下步骤，因为我们将要构建一些伟大的东西：

1.  在 Android Studio 中创建一个新项目。命名为`GetItRight`，然后点击**下一步**按钮。

1.  选择**手机和平板电脑**选项，然后点击**下一步**按钮。

1.  在**为移动设备添加活动**视图中，选择**Google Play 服务**，然后点击**下一步**按钮。

1.  接受**活动名称**和**标题**字段，然后点击**完成**按钮。

1.  将您的网络浏览器指向 Google 开发者控制台，如果您还没有帐户，请登录或注册。您可以在以下网址找到它：[`console.developers.google.com`](https://console.developers.google.com)。

1.  在开发者控制台中，点击游戏选项卡（网页左侧的游戏图标）。

1.  如果被要求，接受服务条款。

1.  点击**设置 Google Play 服务**按钮。

1.  输入应用程序名称`Get It Right Sample`，选择一个类别：**问答**，然后点击**继续**按钮。

1.  在游戏详情视图中，输入描述，然后点击**保存**按钮。

1.  接下来，您需要生成一个 Oauth2 客户端 ID。要这样做，请点击**关联应用**链接。

1.  选择**Android**作为您的操作系统，输入`packt.com.getitright`作为**包名称**，保持其他设置不变，然后点击**保存并继续**按钮。

1.  在第 2 步中，点击**立即授权您的应用**按钮。在**品牌信息**弹出对话框中，点击**继续**按钮。

1.  **客户端 ID**对话框出现。输入`packt.com.getitright`作为包名称。要获取签名证书指纹，打开**终端应用程序**（对于 Windows：命令提示符）并输入：

```kt
keytool -exportcert -alias androiddebugkey -keystore ~/.android/debug.keystore  -list –v

```

1.  如果要求`keystore`密码，默认的调试 keystore 密码是`android`。

1.  复制并粘贴指纹（SHA1），然后点击**创建客户端**按钮。

1.  点击**返回列表**按钮，然后点击**继续下一步**按钮。

1.  在**Android 应用程序详细信息**视图中，您将看到**应用程序 ID**（如果向下滚动一点），我们稍后将需要它。复制其值。

### 排行榜

按照提供的步骤为应用程序添加排行榜：

1.  在网页的左侧，选择**排行榜**，然后点击**添加新排行榜**按钮。将新排行榜命名为`GetItRight Leaderboard`，然后点击**保存**按钮。注意排行榜**ID**。我们稍后会用到它：![排行榜](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_08_02.jpg)

1.  打开项目`app`目录内的`build.gradle`文件，并添加 Google Play 服务的依赖项：

```kt
compile 'com.google.android.gms:play-services:7.5.0'
```

1.  同步您的项目。如果无法解析 Google Play 服务，将生成一个错误，其中包含一个链接，上面写着**安装存储库并同步项目**。点击此链接进行操作。

1.  打开`AndroidManifest.xml`文件，并向应用程序标签添加元数据标记：

```kt
<meta-data 
 android:name="com.google.android.gms.games.APP_ID"android:value="@string/app_id" />
```

1.  此外，将`app_id`添加到`strings.xml`文件中：

```kt
<resources><string name="app_name">GetItRight</string><string name="app_id">your app id</string>
```

1.  在`GooglePlayServicesActivity`类的`onConnected`方法的第一行设置断点。对于`onConnectionFailed`方法的第一行也是如此。使用 Google Play 服务模板和提供的应用 ID，您应该已经能够连接到 Google Play 服务。运行应用程序（调试模式）以查看是否成功。

1.  创建一个新的 Android 资源目录，并选择**layout**作为资源类型；在该目录中创建一个新的布局资源文件，并命名为`activity_google_play_services.xml`。

1.  向`strings.xml`资源文件添加一些新的字符串：

```kt
<string name="incorrect_answer">That is incorrect</string><string name="correct_answer">That is the correct 
 answer!</string><string name="leader_board">LEADER BOARD</string>
```

1.  为`activity_google_play_service`资源文件创建布局：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android=
   "http://schemas.android.com/apk/res/android"android:orientation="vertical"  
    android:layout_width="match_parent"android:padding="16dp"
    android:background="@android:color/holo_blue_dark"
    android:layout_height="match_parent">
    <ScrollView
      android:layout_width="match_parent"
      android:layout_height="wrap_content"><LinearLayout
         android:orientation="vertical"android:layout_width="match_parent"android:layout_height="wrap_content">
          <ImageView
            android:id="@+id/image"android:src= 
             "@android:drawable/ic_popup_sync"android:layout_width="match_parent"android:layout_height="300px" />
          <TextView
            android:id="@+id/text"android:textColor="@android:color/white"android:text="Question"android:textSize="24sp"android:layout_width="match_parent"android:layout_height="wrap_content" />
          <LinearLayout
            android:orientation="vertical"android:layout_width="match_parent"android:layout_height="wrap_content">
          <Button
            android:id="@+id/button_1"            
            android:layout_width="match_parent"android:layout_height="wrap_content"android:gravity="center_vertical|left" />
          <Button
            android:id="@+id/button_2"android:layout_width="match_parent"android:layout_height="wrap_content"                     
            android:gravity="center_vertical|left" />
          <Button
           android:id="@+id/button_3"android:layout_width="match_parent"android:layout_height="wrap_content"android:gravity="center_vertical|left" />
          <Button
           android:id="@+id/button_4"           
           android:layout_width="match_parent"android:layout_height="wrap_content"android:gravity="center_vertical|left" />
          <Button
           android:id="@+id/button_test"android:text="@string/leader_board"android:layout_width="match_parent"android:layout_height="wrap_content"android:gravity="center_vertical|left" />
          </LinearLayout>
        </LinearLayout>
    </ScrollView>
</LinearLayout>
```

1.  打开`GooglePlayServicesActivity`文件。在`onCreate`方法中，加载布局并为所有按钮设置点击监听器：

```kt
setContentView(R.layout.activity_google_play_services); 
findViewById(R.id.button_1).setOnClickListener(this);
findViewById(R.id.button_2).setOnClickListener(this);
findViewById(R.id.button_3).setOnClickListener(this);
findViewById(R.id.button_4).setOnClickListener(this); 
findViewById(R.id.button_test).setOnClickListener(this);
```

1.  为`GooglePlayServicesActivity`文件实现`onClickListener`方法。Android Studio 将建议一个实现，您可以接受此建议，也可以自己添加实现：

```kt
public class GooglePlayServicesActivity extends Activity implements GoogleApiClient.ConnectionCallbacks,GoogleApiClient.OnConnectionFailedListener, 
   View.OnClickListener { 
@Override
public void onClick(View v) {
}
```

1.  添加两个私有成员，一个用于我们的排行榜请求，另一个用于保存您的排行榜 ID：

```kt
private int REQUEST_LEADERBOARD = 1;
private String LEADERBOARD_ID = "<your leaderboard id>";
```

1.  为`onClick`方法创建实现。我们正在准备用户点击多项选择选项的情况。对于**排行榜**（测试）按钮，我们可以立即添加实现：

```kt
@Override
public void onClick(View v) {
    switch (v.getId()){
        case R.id.button_1:
        case R.id.button_2:
        case R.id.button_3:
        case R.id.button_4: 
            break;
        case R.id.button_test:
         startActivityForResult( 
          Games.Leaderboards.getLeaderboardIntent(  
           mGoogleApiClient, LEADERBOARD_ID),  
            REQUEST_LEADERBOARD);
         break;
    }
}
```

1.  创建一个新的包并命名为`models`。创建`Answer`、`Question`和`Quiz`类：

要添加`Answer`类，您需要以下代码：

```kt
public class Answer {
    private String mId;
    private String mText;
    public String getId() {
        return mId;
    }
    public String getText() {
       return mText;
    }
    public Answer (String id, String text) {
        mId = id;
        mText = text;
    }
}
```

要添加`Question`类，请使用以下代码：

```kt
public class Question {
    private String mText;
    private String mUri;
    private String mCorrectAnswer;
    private String mAnswer;
    private ArrayList<Answer> mPossibleAnswers;
    public String getText(){
        return mText;
    }
    public String getUri(){
        return mUri;}
    public String getCorrectAnswer(){
        return mCorrectAnswer;
    }
    public String getAnswer(){
        return mAnswer;
    }
    public Question (String text, String uri, String 
     correctAnswer){
        mText = text;
        mUri = uri;
        mCorrectAnswer = correctAnswer;
    }
    public Answer addAnswer(String id, String text){
        if (mPossibleAnswers==null){
            mPossibleAnswers = new ArrayList<Answer>();
        }
        Answer answer = new Answer(id,text);
        mPossibleAnswers.add(answer);
        return answer;
    }
    public ArrayList<Answer> getPossibleAnswers(){
        return mPossibleAnswers;
    }
}
```

要添加`Quiz`类，请使用以下代码：

```kt
public class Quiz {
    private ArrayList<Question> mQuestions;
    public ArrayList<Question> getQuestions(){
        return mQuestions;
    }
    public Question addQuestion(String text, String uri, String 
     correctAnswer){
        if (mQuestions==null){
            mQuestions = new ArrayList<Question>();
        }
        Question question = new Question( 
         text,uri,correctAnswer);
        mQuestions.add(question);
        return question;
    }
}
```

1.  创建一个新的包并命名为`repositories`。创建一个新的类并命名为`QuizRepository`。向测验添加一些问题。您可以使用以下示例中的问题，但如果愿意，也可以自己创建一些问题。在真实的应用程序中，问题和答案当然不会是硬编码的，而是从数据库或后端检索的（请注意，我们随时可以更改此行为，而无需修改除此类之外的任何内容）：

```kt
public class QuizRepository {
    public Quiz getQuiz(){
      Quiz quiz = new Quiz();
      Question q1 = quiz.addQuestion(
      "1\. What is the largest city in the world?",  
       "http://cdn.acidcow.com/pics/20100923/
        skylines_of_large_cities_05.jpg" , "tokyo");
        q1.addAnswer("delhi" , "Delhi, India");
        q1.addAnswer("tokyo" , "Tokyo, Japan");
        q1.addAnswer("saopaulo" , "Sao Paulo, Brazil");
        q1.addAnswer("nyc" , "New York, USA");
        Question q2 = quiz.addQuestion("2\. What is the largest animal in the world?","http://www.onekind.org/uploads/a-z/az_aardvark.jpg" , "blue_whale");
        q2.addAnswer("african_elephant" , "African Elephant");
       q2.addAnswer("brown_bear" , "Brown Bear");
        q2.addAnswer("giraffe" , "Giraffe");
        q2.addAnswer("blue_whale" , "Blue whale");
        Question q3 = quiz.addQuestion("3\. What is the highest mountain in the world?","http://images.summitpost.org/medium/ 815426.jpg", "mount_everest");
        q3.addAnswer("mont_blanc" , "Mont Blanc");
        q3.addAnswer("pico_bolivar" , "Pico Bolívar");
        q3.addAnswer("mount_everest" , "Mount Everest");
        q3.addAnswer("kilimanjaro" , "Mount Kilimanjaro");
        return quiz;
    }
}
```

1.  在`GamePlayServicesActivity`类中，添加这三个私有成员：

```kt
private Quiz mQuiz;
private int mScore;
private int mQuestionIndex=0;
```

1.  为`newGame`方法添加实现。我们将通过向存储库请求来获取`Quiz`对象。重置分数和问题索引后，我们调用`displayQuestion`方法，该方法通过实际显示问题、可能的答案和漂亮的图片来实现 UI 逻辑：

```kt
private void newGame(){
    mQuiz = new QuizRepository().getQuiz();
    mScore = 0;
    mQuestionIndex = 0;
    displayQuestion(mQuiz.getQuestions().get(mQuestionIndex));
private void displayQuestion(Question question){ 
    TextView questionText = (TextView)findViewById(R.id.text); 
    displayImage(question); 
    questionText.setText(question.getText());
    ArrayList<Answer> answers = question.getPossibleAnswers();
    setPossibleAnswer(findViewById(R.id.button_1), 
     answers.get(0));
    setPossibleAnswer(findViewById(R.id.button_2), 
     answers.get(1));
    setPossibleAnswer(findViewById(R.id.button_3), answers.get(2));
    setPossibleAnswer(findViewById(R.id.button_4), answers.get(3));
}
private void setPossibleAnswer(View v, Answer answer){
    if (v instanceof Button) {
        ((Button) v).setText(answer.getText());
        v.setTag(answer);
    }
}
private void displayImage(final Question question){ 
    new Thread(new Runnable() {
        public void run(){
            try {
              URL url = new URL(question.getUri());
              final Bitmap image = BitmapFactory.decodeStream(url.openConnection().getInputStream());
               runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        ImageView imageView = (ImageView) 
                          findViewById(R.id.image);
                        imageView.setImageBitmap(image);
                    }
                });
            }
            catch (Exception ex){
                Log.d(getClass().toString(), ex.getMessage());
            }
        }
    }).start();
}
```

### 让游戏开始！

以下步骤可用于添加新游戏的方法：

1.  在`onCreate`方法的末尾，我们将调用`newGame`方法：

```kt
newGame();
```

1.  修改`onClick`方法，这样当用户点击任何按钮时我们可以做出响应。如果点击了任何一个多选按钮，我们将调用`checkAnswer`方法。我们选择的是正确答案吗？多么令人兴奋：

```kt
@Override
public void onClick(View v) {
    switch (v.getId()){
        case R.id.button_1:
        case R.id.button_2:
        case R.id.button_3:
        case R.id.button_4:
            checkAnswer(v);
            break;
        case R.id.button_test: startActivityForResult( 
         Games.Leaderboards.getLeaderboardIntent(
          mGoogleApiClient, LEADERBOARD_ID), REQUEST_LEADERBOARD);
         break;
}

   }
```

1.  添加`checkAnswer`方法。我们将比较给定答案与问题的正确答案，根据结果，我们将调用`onGoodAnswer`或`onWrongAnswer`方法。根据答案，你的进展将被决定：如果答案错误，游戏结束，我们将显示排行榜。

1.  如果没有更多的问题，我们将提交用户的分数并显示排行榜。排行榜本身将处理所有相关逻辑。提交的分数是否足够高，使你的名字出现在榜单的顶部？通过以下片段来检查：

```kt
private void checkAnswer(View v){ 
    if (v instanceof Button){
        Answer answer = (Answer)((Button)v).getTag();
        if (mQuiz.getQuestions().get(mQuestionIndex).  
         getCorrectAnswer().equalsIgnoreCase( 
          answer.getId())){
            onGoodAnswer();
        }
        else{
            onWrongAnswer();
        }
    }
}
private void onWrongAnswer(){
    Toast.makeText(this, getString( 
     R.string.incorrect_answer), Toast.LENGTH_SHORT).show();
    startActivityForResult(
     Games.Leaderboards.getLeaderboardIntent( 
     mGoogleApiClient, LEADERBOARD_ID), 
      REQUEST_LEADERBOARD);
}
private void onGoodAnswer(){
    mScore+= 1000;
    Games.Leaderboards.submitScore(mGoogleApiClient, 
     LEADERBOARD_ID, mScore);
    Toast.makeText(this, getString(R.string.correct_answer), 
     Toast.LENGTH_SHORT).show();
    mQuestionIndex++;
    if (mQuestionIndex < mQuiz.getQuestions().size()){
        displayQuestion(mQuiz.getQuestions().get( 
         mQuestionIndex));
    }
    else{
        startActivityForResult( 
         Games.Leaderboards.getLeaderboardIntent( 
          mGoogleApiClient, LEADERBOARD_ID), 
           REQUEST_LEADERBOARD);
	}
}
```

1.  为了做好单元测试和代码检查，让我们添加注释支持。在`app`文件夹中打开`build.gradle`文件并添加依赖项。在修改文件后，点击出现的**立即同步**链接：

```kt
compile 'com.android.support:support-annotations:22.2.0'
```

1.  如果出现“无法解析支持注释”的错误，则点击出现的**安装存储库并同步项目**链接。

1.  如果一切顺利，我们可以添加注释，例如在`CheckAnswer`方法的参数上：

```kt
private void checkAnswer(@NonNull View v){
```

1.  在`Question`类中，我们可以为`getPossibleAnswers`方法添加`@Nullable`注释，如果我们没有为问题提供任何多选选项的话，这可能是情况：

```kt
@Nullable
public ArrayList<Answer> getPossibleAnswers(){
    return mPossibleAnswers;
}
```

1.  稍后，如果我们进行一些分析，这将导致`GooglePlayServiceActivity`出现警告，我们将在*代码分析*中更仔细地查看这一点：

```kt
Method invocation 'answers.get(0)' may produce  'java.lang.NullPointerException' 
```

如果你喜欢，你可以玩这个游戏并添加一些注释。只是不要花太多时间。我们来玩游戏吧！

运行你的应用程序，并成为排行榜上的第一名。因为目前你是唯一的测试玩家，我猜这不会太难。

你刚刚创建了自己的测验应用程序，如果你愿意，可以添加一些其他具有挑战性的问题，如下面的屏幕截图所示：

![让游戏开始吧！](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_08_03.jpg)

我们已经调查了 Google Play 服务，并且我们一直在为我们的应用使用 MVC 方法。此外，我们还研究了如何使用注释，在进行一些代码分析后，这些注释可以帮助我们改进代码。

## 还有更多...

我们只是匆匆一瞥了一下模式以及如何应用它们。查看互联网或获取一些优秀的书籍，以了解更多关于模式的知识。另外，请参阅[`www.google.com/design/spec/patterns/app-structure.html`](https://www.google.com/design/spec/patterns/app-structure.html)。

确保你也阅读了有关支持注释的文档。使用它们有很多更多的可能性。在[`tools.android.com/tech-docs/support-annotations`](http://tools.android.com/tech-docs/support-annotations)中查看文档。

此外，我们只使用了 Google Play 服务的一小部分。我们只知道如何登录和如何使用排行榜。如果你愿意，你可以查看其他选项。有关此内容，请参阅[`developers.google.com/games/services/android/quickstart`](https://developers.google.com/games/services/android/quickstart)。

## 另请参阅

+   参见第七章，*内容提供者和观察者*。

# 使用 Robolectric 进行单元测试

单元测试是一种测试方法，其中测试代码的各个单元。例如，可以测试视图或存储库，以检查它是否满足要求。与大多数其他测试不同，这些测试通常由软件开发人员开发和运行。

理想情况下，一个测试用例完全独立于其他用例和其他单元。由于类通常依赖于其他替代品，例如需要使用模拟对象。在上一个教程中，`QuizRepository`类提供了硬编码的测验数据（存根或模拟数据），但正如建议的那样，意图是测验数据应该从后端获取。

我们将准备好我们在上一个教程中创建的应用程序进行单元测试，并且我们将自己创建一些测试。**Robolectric**将帮助我们完成这些。尽管自 Android Studio 1.2 版本发布以来，基于 JUnit 的单元测试设置变得更加容易，但它仍然不如 Robolectric 强大。

Robolectric 不需要额外的模拟框架，它也可以在模拟器之外运行，这使我们能够将单元测试与持续集成环境结合起来，就像我们将在第十章中所做的那样，*测试你的应用程序*。

## 准备工作

对于这个教程，最理想的情况是上一个教程已经成功完成。如果你选择跳过本章的这一部分，当然可以打开你自己的项目，并以更或多或少相同的方式设置单元测试。这取决于你。

## 如何做...

那么我们要做些什么来创建和运行一些单元测试呢？让我们找出来：

1.  打开我们在上一个教程中创建的项目。

1.  在`app`文件夹中打开`build.gradle`文件，并为 Robolectric 添加一个依赖项：

```kt
testCompile 'org.robolectric:robolectric:3.0'
```

1.  将`src`文件夹中的`androidTest`文件夹重命名为`test`。

1.  从**Run**菜单中选择**Edit configurations**选项。

1.  在 Run\Debug Configuration 窗口的左侧，选择**Defaults**和**JUnit**。在右侧将**Working directory**的内容更改为`$MODULE_DIR$`，然后点击**OK**按钮。

1.  将**ApplicationTest**类重命名为`QuizRepositoryTest`。

1.  向**QuizRepositoryTest**类添加一些测试。我们将使用 Robolectric 进行这项工作。正如你所注意到的，我们将在这里使用注解，就像我们在上一个教程中所做的那样：

```kt
@Config(constants = BuildConfig.class, sdk = 21)
@RunWith(RobolectricGradleTestRunner.class)
public class QuizRepositoryTest {
    private QuizRepository mRepository; 
    @Beforepublic void setup() throws Exception {
       mRepository = new QuizRepository();
        assertNotNull("QuizRepository is not 
        instantiated", mRepository);
    }
    @Test
    public void quizHasQuestions() throws Exception {
        Quiz quiz = mRepository.getQuiz();
        ArrayList<Question> questions = quiz.getQuestions();
        assertNotNull("quiz could not be created", quiz);

        assertNotNull("quiz contains no questions",       
         questions);
        assertTrue("quiz contains no questions", 
         questions.size()>0);
    }
    @Test
    public void quizHasSufficientQuestions() throws 
     Exception {
        Quiz quiz = mRepository.getQuiz();
        ArrayList<Question> questions = quiz.getQuestions();
        assertNotNull("quiz could not be created", quiz);
        assertNotNull("quiz contains no questions", 
         questions);
        assertTrue("quiz contains insufficient questions", questions.size()>=10);
    }
}
```

1.  创建另一个测试类，以便我们可以测试该活动。将新类命名为`GooglePlayServicesActivityTest`。在这个测试中，我们也可以进行一些布局测试：

```kt
@Config(constants = BuildConfig.class, sdk = 21)
@RunWith(RobolectricGradleTestRunner.class)
public class GooglePlayServicesActivityTest {
    private GooglePlayServicesActivity activity;
    @Before
    public void setup() throws Exception {
       activity = Robolectric.setupActivity( 
        GooglePlayServicesActivity.class);
        assertNotNull("GooglePlayServicesActivity is not instantiated", activity);
    }
    @Test
    public void testButtonExistsAndHasCorrectText() throwsException {
        Button testButton = (Button) activity.findViewById( 
         R.id.button_test); 
        assertNotNull("testButton could not be found",testButton); 
}
```

1.  打开`build variants`窗格，并选择`Unit tests`而不是`Instrumentation tests`。

现在`test`包中的所有内容都将被突出显示为绿色（你可能需要先进行重建）。如果你右键单击`packt.com.getitright`包名或者你创建的任何测试类，你将在上下文菜单中找到一个选项**Run tests in packt.com.getright**或**Run QuizRepositoryTest**。例如，选择运行`QuizRepositoryTest`。如果选择此选项，Gradle 会开始思考一会儿。一段时间后，结果会显示出来。

默认情况下只显示失败的测试。要查看成功的测试，点击左侧显示测试树上方的**Hide passed**按钮。

你会看到**quizHasQuestions**测试已经通过。然而，**quizHasSufficientQuestions**测试失败了。这是有道理的，因为我们的测试要求我们的测验至少有 10 个问题，而我们只添加了三个问题到测验中，如下图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_08_04.jpg)

在`QuizRepository`中为`Quiz`添加七个问题，以便做对。当然，你也可以作弊，通过修改测试来达到目的，但我们就说这是一个业务需求吧。

重新运行测试。每个单元测试都成功了。万岁！创建一些你能想到的其他单元测试。

单元测试是一个非常有趣的选择，因为我们也可以将其用于持续集成的目的。想象一下，每次您将源代码提交（和推送）到 GitHub 或 BitBucket 等中央存储库时，我们都运行单元测试的情景。如果编译和所有单元测试都成功，我们可以自动创建一个新的（临时的）发布，或者被通知编译或任何测试失败。

## 还有更多...

还有很多其他工具和方法可用于移动测试目的。

除了单元测试，我们还希望测试**用户界面**（**UI**），例如使用 Espresso。

### Espresso

Espresso 适用于编写简洁可靠的 Android UI 测试。测试通常包含点击、文本输入和检查。编写测试实际上非常简单。以下是使用 Espresso 的测试示例：

```kt
@Test
public void testLogin() {
   onView(withId(R.id.login)).perform(
    typeText("mike@test.com"));
   onView(withId(R.id.greet_button)).perform(click());
}
```

引用网站上的话：

> “*Espresso 测试清楚地陈述期望、交互和断言，而不受到样板内容、自定义基础设施或混乱的实现细节的干扰*”。

有关更多信息，请参阅[`code.google.com/p/android-test-kit/wiki/Espresso`](https://code.google.com/p/android-test-kit/wiki/Espresso)。

### 方法

在测试方面，有不同的方法可以考虑。其中一种方法是**测试驱动开发**（**TDD**）。如果功能和所有要求都已知，我们可以在开发应用程序之前定义我们的测试。当然，所有测试最初都会失败，但这实际上是件好事。它将概述需要做的事情，并集中精力做正确的事情。如果您开始开发得越来越多，测试将成功，剩下的工作量也会减少。

另一种更近期的方法是**行为驱动开发**（**BDD**）。这种测试方法是基于功能的，其中一个功能是从特定的角度表达的一系列故事。

BDD 工具可以作为单元测试的一种风格，例如`Rspec`，也可以作为更高级别的验收测试风格：`Cucumber`。

### Cucumber、Gherkin 和 Calabash

不，这不是突然出现在这里的蔬菜店广告。**Cucumber**是一种以 BDD 风格编写的自动化验收测试的工具。它允许执行以业务面向文本编写的功能文档。

以下是使用**Gherkin**的功能文件的示例。它有两个目的：文档和自动化测试：

```kt
Scenario: Login
  Given I am on the Login Screen
  Then I touch the "Email" input field
  Then I use the keyboard and type "test@packt.com"
  Then I touch the "Password" input field
  Then I use the keyboard and type "verysecretpassword"
  Then I touch "LOG IN"
  Then I should see "Hello world"
```

`Gherkin`是一种可读性强的领域特定语言，它可以让您描述软件的行为，而不详细说明该行为是如何实现的。因此，非开发团队成员也可以编写这些测试。

需要一些粘合代码来使事情发生。在 Cucumber 中，这个过程是在步骤定义中定义的。Cucumber 通常让您用 Ruby 语言编写这些步骤定义。

通过 Calabash 框架，您可以使用 Cucumber 为 Android 和 iOS 创建测试。它使您能够定义和执行自动化验收测试。Calabash 的另一个很棒的地方是，它允许您在云上运行自动化测试，例如使用 TestDroid 的服务。

### 首先要做的事情！

要了解有关 Cucumber 的更多信息，请访问[`cucumber.io`](https://cucumber.io)。

您可以在[`calaba.sh`](http://calaba.sh)找到 Calabash 框架。

还可以查看[www.testdroid.com](http://www.testdroid.com)了解有关使用 TestDroid 云测试环境在尽可能多的设备上进行测试的更多信息。

最后，要在时间、质量和金钱之间找到一个良好的平衡。测试应用程序的方法取决于您（或您的公司或您的客户）认为这些元素中的每个元素有多有价值。至少创建单元测试和 UI 测试。还要不要忘了性能测试，但这是下一章将讨论的一个话题！

## 另请参阅

+   参考第九章，*性能改进*

+   参考第十章，*测试您的应用程序的 Beta 版*

# 代码分析

代码分析工具，如 Android Lint，可以帮助你检测潜在的错误，以及如何优化你的应用程序的安全性、可用性和性能。

Android Lint 随 Android Studio 一起提供，但也有其他可用的工具，如：Check Style，**项目** **Mess Detector**（**PMD**）和 Find Bugs。在这个示例中，我们只会看一下 Android Lint。

## 准备工作

+   最理想的情况是，你已经完成了本章的前两个示例，所以我们现在将检查应用的结果。但是，你也可以在任何项目上使用`Android Lint`（或其他工具）来查看哪里可以改进。

### 注意

第一个示例的支持注解影响了显示的结果。是的，没错，我们引起了这些警告。

## 操作步骤...

我们不需要安装任何东西来获取 Android Lint 报告，因为它已经在 Android Studio 中了。只需按照下一步骤来使用它：

1.  打开你在之前示例中创建的项目。或者，打开你自己的项目。

1.  从**分析**菜单中选择**代码检查**。检查范围是整个项目。单击**确定**按钮继续。

1.  检查结果将以树形视图呈现。展开并选择项目以查看每个项目的内容，如下面的快照所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_08_05.jpg)

1.  这里看起来很严重，但实际上并不是那么糟糕。有一些问题根本不是致命错误，但修复它们可以极大地改进你的代码，这正是我们目前的目标。

1.  例如，查看**声明冗余** | **声明访问可以更弱** | **可以是私有**问题。导航到它。双击它跳转到问题出现的代码。右键单击它。上下文菜单立即提供了解决方案。选择**使字段私有**选项应用正确的解决方案。如果这样做，此项目将被标记为已完成（划掉）。

1.  现在看看**硬编码文本**。如果你双击与此问题相关的任何项目，你会看到问题所在。

1.  为了方便起见，我们放置了一个临时文本（如`Text View`中的`Question`）。如果这是真的，我们应该使用一个字符串资源。在这里，我们可以安全地删除这个文本。如果你重新运行代码检查，问题将消失：

```kt
<TextView
    android:id="@+id/text"android:textColor="@android:color/white"android:textSize="24sp"android:layout_width="match_parent"
    android:layout_height="wrap_content" />
```

1.  接下来，看看**常量条件和异常**下的**可能的错误**。对于`GooglePlayServicesActivity`文件，它说：

```kt
Method invocation 'answers.get(0)' may produce 'java.lang.NullPointerException'
```

1.  如果你双击这条消息，你会发现问题所在：

```kt
setPossibleAnswer(findViewById(R.id.button_1), answers.get(0));
```

1.  这一行可能会产生`Null Pointer Exception`。为什么？如果你通过选择并按下*Cmd* + *B*（对于 Windows：*Ctrl* + *B*）来查看`getPossibleAnswers`方法的声明，你就会找到原因：

```kt
@Nullable
public ArrayList<Answer> getPossibleAnswers(){return mPossibleAnswers;}
```

啊对了！我们在第一个示例中自己添加了这个注解，以提醒我们以后（或其他开发人员）返回的答案可能为空。有几种方法可以解决这个问题。

1.  我们可以在这里删除`@Nullable`注解，但那样做是不好的，因为答案实际上可能是空的。我们也可以选择忽略这个警告。

1.  最好的解决方案是在执行任何操作之前实际测试`getAnswers`方法的结果。就像这样：

```kt
ArrayList<Answer> answers = question.getPossibleAnswers();
if (answers == null){
    return;
}
```

1.  展开**声明冗余** | **方法可以是 void** | **问题**。它说：

```kt
Return value of the method is never used 

```

1.  双击问题跳转到代码。嗯，那个警告是正确的，但假设我确实想要返回答案，因为我相当确定（你能有多确定？）我以后会使用它。在这种情况下，你可以右键单击问题，选择**对成员进行抑制**选项。你将不会再被这个问题打扰，因为它会在你的代码中添加`SuppressWarnings`注释：

```kt
@SuppressWarnings("UnusedReturnValue")public Answer addAnswer(String id, String text){
```

1.  最后，看看**拼写警告**。展开**拼写**和底层的**拼写错误**和**应用**项目。就在那里。一个`拼写错误`！

```kt
Typo: In word 'getitright' 

```

我们现在没有**getitright**，是吗？由于这是我们应用程序的名称，也是包名称的一部分，我相当确定我们可以安全地忽略这个警告。这一次，我们右键单击类型，选择**保存到字典**选项：

1.  警告列表似乎是无穷无尽的，但所有这些项目有多严重呢？在 Android Studio 的左侧，你会找到一个带有**按严重性分组**工具提示的按钮。点击它。

1.  现在树视图包含一个错误节点（如果有的话），一个警告节点和一个拼写错误节点。如果你只专注于错误和警告，并了解每个项目是关于什么，那么你将改进你的代码，并且实际上会学到很多，因为每个问题都附带了问题的描述和如何修复的建议。

很好，你今天学到了一些很酷的东西！并且通过应用模式、运行单元测试以及修复`Android Lint`报告的问题来编写更好的代码。

我们现在知道我们的应用程序做了它应该做的事情，并且在一些重构之后它结构良好。

接下来要想的是，如果我们从互联网加载的图像是现在的 10 倍大小会发生什么？如果我们有 1000 个问题呢？不真实？也许。

我们的测验应用在低端设备上的表现如何？在下一章中，我们将寻找这些和其他问题的答案。

## 另请参阅

+   参考第九章, *性能*

+   参考第十章, *测试您的应用程序的 Beta 版*


# 第九章：改善性能

性能很重要，因为它会影响您的应用在 Google Play 商店上的评价。我们想要一个五星级的应用！在高端设备上，您的应用可能会顺利运行，没有任何问题，但在用户的低端设备上，情况可能会有所不同。它可能运行缓慢或者内存不足，导致应用崩溃。

![改善性能](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_01.jpg)

在本章中，您将学习以下配方：

+   内存分析器和性能工具

+   糟糕的应用程序-性能改进

+   过度绘制问题

# 介绍

我们如何检测我们的应用是否会有性能问题？Android 应用程序中常见的问题是什么？我们如何解决这些问题？

在性能方面，可能会出现一些问题，如下所示：

+   **内存泄漏**：尽管 Android 配备了自己的内存管理系统，但可能会发生内存泄漏。

+   **内存不足异常**：您的应用程序可能会很容易耗尽内存，导致应用程序崩溃。例如，在低端设备上处理大图像时会出现这种情况。

+   **过度绘制**：过度绘制是指视图上的像素被绘制多次的现象。它可能导致用户界面无响应或延迟。

在接下来的示例中，我们将检查这里列出的问题。Android SDK 和 Android Studio 都配备了一些很好的工具来检查您的应用。

# 内存分析器和性能工具

您的应用程序可能会受到内存泄漏或分配过多内存的影响。

**垃圾收集器**（**GC**）负责清理我们不再需要使用的任何东西，这是一个很好的帮手，但不幸的是，它并不完美。它只能删除被识别为不可达的对象。未清理的对象会一直占用空间。过一段时间，如果创建了越来越多的对象，就可能会发生`OutOfMemoryError`，就像尝试加载一些大图像时会发生的情况，这是许多 Android 应用程序常见的崩溃场景。

内存泄漏有些难以发现。幸运的是，Android Studio 配备了内存监视器。它可以为您提供应用程序内存使用情况的概述，并提供一些关于内存泄漏的线索。

我们将使用这个**内存监视器**来找出是否不需要的 GC 事件模式导致了性能问题。除此之外，我们将使用**分配跟踪器**来确定代码中可能存在的问题所在。

## 准备工作

对于这个配方，如果您已经完成了前几章中的任何一个配方，那将是很好的。如果可能的话，它应该是从互联网获取数据（文本和图像）的配方，例如第二章中的应用程序，*具有基于云的后端的应用程序*。当然，任何其他应用程序都可以，因为我们将检查工具来检查我们的应用程序以改进它。

## 如何做...

让我们看看我们的应用程序的性能如何！

1.  启动 Android Studio 并打开您选择的应用程序。

1.  在设备上运行您的应用程序（或使用虚拟 Genymotion 设备）。

1.  **内存监视器**位于**内存**选项卡上，您可以在**Android**选项卡上找到它。

1.  如果没有显示，请使用*Cmd* + *6*（对于 Windows：*Alt* + *6*）快捷键使其出现。

1.  运行您的应用程序，查看内存监视器记录您的应用程序的内存使用情况。在下面的示例中，我运行了一个从 FourSquare API 加载了 200 个场馆（包含文本和图片）的应用程序。每次我按下按钮时，我会请求 200 个更多的场馆，导致图表中显示的峰值。请给我更多附近的咖啡店：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_02.jpg)

1.  应用的内存使用显示为深蓝色。未分配的内存显示为浅蓝色。当您的应用开始运行时，分配的内存会增长，直到没有更多的内存，或者当 GC 到达并完成其工作时，它会减少。

1.  这些都是常见的事件，最终，您可以通过单击左侧窗口上方的“内存”选项卡上的“启动 GC”图标（**Initiate GC**）来自己调用 GC。

1.  只有在短时间内分配了大量内存或 GC 事件更频繁时才会引起怀疑。您的应用程序可能存在内存泄漏。

1.  同样，您可以监视 CPU 使用情况。您可以在**Android**面板的**CPU**选项卡上找到它。如果您在这里注意到非常高的峰值，那么您的应用程序可能做得太多了。在下面的截图中，一切看起来都很好：![如何操作...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_03.jpg)

1.  要了解更多关于内存问题的信息，我们可以使用另一个工具。从“工具”菜单中，选择“Android”和“Android 设备监视器”选项。该工具带有堆视图、内存监视器和分配跟踪器，这些都是提供有关应用程序使用的内存的见解的工具。

1.  如果尚未选择，请单击顶部导航栏上出现的“Dalvik 调试监视器服务器”（**DDMS**）按钮。`DDMS`是一个提供线程和堆信息以及其他一些内容的调试工具。

1.  选择“堆”选项卡。在窗口的右侧，选择应用程序，应该会出现在设备名称的下方。如果找不到您的应用程序，可能需要重新运行您的应用程序。![如何操作...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_04.jpg)

1.  内存请求将通过从内存池中分配部分来处理，这称为堆。在任何给定时间，堆的某些部分正在使用，而某些部分未使用，因此可供将来分配使用。

1.  **堆**选项卡可以帮助您诊断内存泄漏，显示系统为您的应用程序分配了多少内存。在这里，您可以确定意外或不必要地分配的对象类型。如果分配的内存不断增加，那么这是您的应用程序存在内存泄漏的强烈迹象。

### 注意

如果未启用堆更新，请查看“设备”选项卡上的按钮。单击“更新堆”按钮（截图左侧第二个按钮）。

1.  堆输出仅在 GC 事件之后显示。在堆选项卡上，找到“Cause GC”按钮并单击它以强制 GC 执行其工作。之后，“堆”选项卡将看起来有点像这样：![如何操作...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_05.jpg)

1.  在上面的截图中显示了关于应用程序堆使用情况的大量信息。单击表中的任何项目以获取更多信息。这里显示的信息可以帮助您确定应用程序的哪些部分导致了太多的分配。也许，您需要减少分配的数量或更早释放内存。

1.  为了更好地了解您的应用程序的关键部分以及确切导致问题的堆栈跟踪，您可以单击“分配跟踪器”选项卡。

1.  在该选项卡上，单击“开始跟踪”按钮。

1.  以某种方式与您的应用程序进行交互，例如刷新列表，转到详细视图或您的应用程序所做的任何操作，并且您想要测量。

1.  单击“获取分配”按钮以更新分配列表。

1.  作为您为应用程序启动的操作的结果，您将在此处看到所有最近的分配。

1.  要查看堆栈跟踪，请单击任何分配。在下一个示例中，我们正在调查在表行中加载图像。跟踪显示了在哪个线程中分配了什么类型的对象以及在哪里。![如何操作...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_06.jpg)

如果愿意，您可以玩一下，以更多了解 Android 设备监视器。既然您已经看到了一些测量结果的工具，让我们更仔细地看看如何处理它们以及如何避免内存问题。我们下一节再见！

## 还有更多...

**Android 设备监视器**和 Android Studio 附带的内存工具都有许多其他选项可供您探索。这些选项将帮助您提高应用程序的质量和性能。这将使您和您的应用程序用户感到满意！

## 另请参阅

+   第二章, *具有基于云的后端的应用程序*

+   第八章, *提高质量*

+   第十章, *测试您的应用程序*

# 这里是一个糟糕的应用程序 - 性能改进

在 Android 应用程序开发中，有哪些应该做和不应该做的事情，以避免性能问题，即使这些问题可能不会在您自己的设备上出现？测试 Android 应用程序很困难，因为有这么多的设备。谨慎写代码总比抱憾写代码要好。

有人说编写高效代码有两个基本规则：不要做不需要做的工作（因此来自第八章的 DRY 和 YAGNI 原则，*提高质量*），如果可以避免的话，不要分配内存。除此之外，还有一点很有趣，那就是有各种可用的库，它们不仅可以节省您的时间，而且还可以证明非常高效。当然，重新发明轮子也可能出现错误。

例如，考虑`RetroFit`库，它将使编写用于消耗网络服务的代码变得更加容易，或者考虑`Picasso`，这是一个图像加载库，它将通过一行代码从 URL 加载图像，而无需过多担心诸如线程、图像大小调整、转换或内存管理等问题。

总的来说，一些良好的做法如下：

+   优化位图内存使用。

+   在隐藏用户界面时释放内存。

+   不要在布局中使用太多嵌套视图。

+   不要创建不必要的对象、类或内部类。

+   在可能的情况下，使用原始类型而不是对象。

+   如果您不需要对象的任何成员，最好使用静态方法而不是虚拟方法。静态调用会更快。

+   尽量避免使用内部的 getter 和 setter，因为在 Android 中直接访问字段要快得多。

+   如果整数可以胜任，就不要使用浮点数。

+   如果注册了监听器，那么一定要确保取消注册。在活动生命周期的相应对中注册和取消注册。例如，在`onCreate`方法中注册，然后在`onDestroy`方法中取消注册。或者，在`onResume`方法中注册，然后在`onPause`方法中取消注册。

+   如果某个操作花费的时间超过几秒钟，请向用户提供反馈。让用户知道您的应用程序并没有死机，而是在忙着处理！通过显示进度指示器来显示正在进行的操作。

+   始终进行测量。使用性能工具来了解您的应用程序的表现如何。

### 提示

**Android Studio 提示**

您在寻找什么吗？按两次*Shift*键，然后开始输入您要搜索的内容。或者，要显示所有最近的文件，请使用*Cmd* + *E*（对于 Windows：*Ctrl* + *E*）快捷键。

## 准备就绪

对于这个示例，您只需要安装并运行 Android Studio，最好还有一个具有互联网访问权限的真实设备。

## 如何做...

让我们创建一个真正糟糕的应用程序，这样我们就有东西可以修复。我们不会优化位图内存使用。我们会大量使用嵌套视图，做一些其他非常糟糕的事情，对于这个示例，我们将显示有史以来最糟糕的电影列表。这就是糟糕的应用程序：

1.  在 Android Studio 中创建一个新项目。

1.  将其命名为`BadApp`，然后单击**下一步**按钮。

1.  勾选**手机和平板电脑**选项，然后单击**下一步**按钮。

1.  选择**空白活动**，然后单击**下一步**按钮。

1.  接受名称并单击**完成**按钮。

1.  打开`activity_main.xml`布局，并用一个具有漂亮背景颜色的列表视图替换内容，该列表视图位于具有另一个漂亮背景颜色的相对布局中。我们这样做是因为我们想在下一个示例中演示概述问题：

```kt
<RelativeLayout xmlns:android=  
  "http://schemas.android.com/apk/res/android"

    android:layout_width="match_parent"
    android:layout_height="match_parent" 
    android:paddingLeft="@dimen/activity_horizontal_margin"
android:paddingRight="@dimen/activity_horizontal_margin"
    android:paddingTop="@dimen/activity_vertical_margin"
    android:background="@android:color/holo_orange_dark"
    android:paddingBottom="@dimen/activity_vertical_margin" 
    tools:context=".MainActivity">
   <ListView
       android:id="@+id/main_list"
       android:background="@android:color/holo_blue_bright"
       android:layout_width="match_parent"
       android:layout_height="match_parent"></ListView>
</RelativeLayout>
```

1.  创建一个新的布局文件，命名为`adapter.xml`。让我们有一些嵌套视图和许多背景颜色。都是为了糟糕的应用程序。

```kt
<?xml version="1.0" encoding="utf-8"?>
<FrameLayout xmlns:android= 
 "http://schemas.android.com/apk/res/android"
    android:orientation="vertical"    
    android:layout_width="match_parent"
    android:background="@android:color/holo_green_light"
    android:padding="8dp"android:layout_height="match_parent">
    <ImageView
        android:id="@+id/main_image"
        android:src="img/ic_media_play"android:layout_marginTop="8dp"android:layout_width="80dp"android:scaleType="fitCenter"android:layout_height="60dp" />
    <TableLayout
        android:layout_marginTop="8dp"android:layout_marginLeft="90dp"android:layout_width="match_parent"android:layout_height="wrap_content"><TableRow android:background=  
          "@android:color/holo_purple">
            <TextView android:layout_width="match_parent"
                android:id="@+id/main_text_title"
                android:layout_marginTop="8dp"
                android:textSize="24sp"
                android:layout_height="wrap_content"
                android:textColor="@android:color/white"/>
    </TableRow>
        <TableRow android:background=
           "@android:color/holo_blue_light">
             <TextView android:layout_width="match_parent"android:id="@+id/main_text_year"android:layout_height="wrap_content"android:textSize="20sp"android:layout_marginTop="8dp"android:textColor="@android:color/white"/></TableRow>
        <TableRow android:background= 
           "@android:color/holo_green_dark">
           <LinearLayout
               android:orientation="vertical"android:layout_height="wrap_content"android:layout_width="match_parent"android:layout_marginTop="16dp">
               <TextView android:layout_width="match_parent"android:id="@+id/main_text_genre"android:layout_height="wrap_content"android:textSize="16sp"android:layout_marginTop="8dp"android:background=   "@android:color/holo_green_dark"android:textColor="@android:color/white"/>
                <TextView android:layout_width="match_parent"android:id="@+id/main_text_director"android:layout_height="wrap_content"android:textSize="16sp"android:layout_marginTop="8dp"android:background=
                    "@android:color/holo_green_light"android:textColor="@android:color/white"/>
               <TextView android:layout_width="match_parent"android:id="@+id/main_text_actors"android:layout_height="wrap_content"android:textSize="16sp"android:layout_marginTop="8dp"android:background=  "@android:color/holo_green_dark"android:textColor="@android:color/white"/></LinearLayout>
        </TableRow>
    </TableLayout>
</FrameLayout>
```

1.  打开`AndroidManifest.xml`文件，并添加对互联网访问的权限：

```kt
<uses-permission android:name="android.permission.INTERNET" />
```

1.  创建一个新类，命名为`BadMovie`：

```kt
public class BadMovie {
    public String title;
    public String genre;
    public String year;
    public String director;
    public String actors;
    public String imageUrl;
    public BadMovie(String title, String genre, String 
     year, String director, String actors, String 
      imageUrl){
        this.title = title;
        this.genre = genre;
        this.year =year;
        this.director = director;
        this.actors = actors;
        this.imageUrl = imageUrl;
    }
}
```

1.  创建一个适配器类，命名为`MainAdapter`。我们将使用`ViewHolder`类，并创建一个单独的线程从网络加载每个电影图像：

```kt
public class MainAdapter  extends ArrayAdapter<BadMovie> {
    private Context mContext;
    private int mAdapterResourceId;
    public List<BadMovie> Items = null;
    static class ViewHolder
        TextView title;
        TextView genre;
        ImageView image;
        TextView actors;
        TextView director;
        TextView year;
    }
    @Override
    public int getCount() {
        super.getCount();
        int count = Items != null ? Items.size() : 0;
        return count;
    }
    public MainAdapter(Context context, int adapterResourceId, 
     List<BadMovie> items) {
        super(context, adapterResourceId, items);
        this.Items = items;
        this.mContext = context;
        this.mAdapterResourceId = adapterResourceId;
    }
    @Override
	public View getView(int position, View convertView, 
     ViewGroup parent) {
        View v = null;
        v = convertView;
        if (v == null) {
            LayoutInflater vi = (LayoutInflater)    
            this.getContext().getSystemService(
             Context.LAYOUT_INFLATER_SERVICE);
            v = vi.inflate(mAdapterResourceId, null);
            ViewHolder holder = new ViewHolder();
            holder.title = (TextView) v.findViewById(
             R.id.main_text_title);
            holder.actors = (TextView) v.findViewById(
             R.id.main_text_actors);
            holder.image = (ImageView)       
             v.findViewById(R.id.main_image);
            holder.genre = (TextView)   
             v.findViewById(R.id.main_text_genre);
            holder.director = (TextView) 
             v.findViewById(R.id.main_text_director);
            holder.year = (TextView) 
             v.findViewById(R.id.main_text_year);
            v.setTag(holder);
        }

        final BadMovie item = Items.get(position); 
        if (item != null) {final ViewHolder holder = (ViewHolder) v.getTag();
           holder.director.setText(item.director);
           holder.actors.setText(item.actors);
           holder.genre.setText(item.genre);
           holder.year.setText(item.year);
           holder.title.setText(item.title);
           new Thread(new Runnable() {
            public void run(){
             try {
              final Bitmap bitmap = 
               BitmapFactory.decodeStream((
                InputStream) new  
               URL(item.imageUrl).getContent());
              ((Activity)getContext()).runOnUiThread(new  
              Runnable() {
                  @Override
                  public void run() {                    
                     holder.image.setImageBitmap(bitmap);
                   }
                });
             } 
             catch (Exception e) {
               e.printStackTrace();
             }
            }
          }).start();}
        return v;
    }
}
```

1.  在`MainActivity`文件中，添加一个包含所有电影的私有成员：

```kt
private ArrayList<BadMovie> mBadMovies;
```

1.  在`onCreate`方法中添加实现，以添加几千部糟糕的电影，为它们创建一个适配器，并告诉列表视图相关信息：

```kt
mBadMovies = new ArrayList<BadMovie>();
for (int iRepeat=0;iRepeat<=20000;iRepeat++) {
    mBadMovies.add(new BadMovie("Popstar", "Comedy", "2000", "Paulo Segio de Almeida", "Xuxa Meneghel,Luighi Baricelli", "https://coversblog.files.wordpress.com/2009/03/xuxa-popstar.jpg"));
    mBadMovies.add(new BadMovie("Bimbos in Time", "Comedy","1993", "Todd Sheets", "Jenny Admire, Deric Bernier","http://i.ytimg.com/vi/bCHdQ1MB1D4/maxresdefault.jpg"));
    mBadMovies.add(new BadMovie("Chocolat", "Comedy", "2013", "Unknown", "Blue Cheng-Lung Lan, MasamiNagasawa", "http://i.ytimg.com/vi/EPlbiYD1MmM/maxresdefault.jpg"));
    mBadMovies.add(new BadMovie("La boda o la vida", "1974", "year", "Rafael Romero Marchent", "Manola Codeso, La Polaca", "http://monedasycolecciones.com/10655-thickbox_default/la-boda-o-la-vida.jpg"));
    mBadMovies.add(new BadMovie("Spudnuts", "Comedy", "2005", "Eric Hurt", "Brian Ashworth, Dave Brown, Mendy St. Ours", "http://lipponhomes.com/wp-content/uploads/2014/03/DSCN0461.jpg"));}

//source: www.imdb.com
MainAdapter adapter = new MainAdapter(this, R.layout.adapter, mBadMovies);
((ListView)findViewById(R.id.main_list)).setAdapter(adapter);
```

1.  现在运行您的应用程序。根据**互联网电影数据库**（**IMDB**）的用户，这些是有史以来最糟糕的喜剧电影。我们故意多次添加了这些电影，以创建一个巨大的列表，其中每一行都使用了从互联网加载缩略图的原始方法，如下图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_07.jpg)

1.  根据您测试应用程序的设备，您可能需要滚动一段时间，或者错误可能会立即出现。

1.  这是迟早会出现在**LogCat**中的。在应用程序崩溃后，检查日志。使用*Cmd* + *6*快捷键（对于 Windows：*Alt* + *6*）显示**LogCat**。它会显示类似于这样的内容：

```kt
packt.com.thebad E/AndroidRuntime﹕ FATAL EXCEPTION: Thread-3529
java.lang.OutOfMemoryError: Failed to allocate a 7238412 byte allocation with 53228 free bytes and 51KB until OOM
```

1.  这就是发生的地方：

```kt
At packt.com.thebad.MainAdapter$1.run(MainAdapter.java:82)
```

1.  还要查看内存和 CPU 监视器。您的设备很难受。如果您滚动列表，就会出现这种情况。

以下屏幕截图提供了**内存**报告：

![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_08.jpg)

以下屏幕截图提供了**CPU**报告：

![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_09.jpg)

1.  如果您想多次加载全尺寸图像，就会得到这样的结果。由于我们无论如何都显示缩略图，因此没有必要这样做，而且您的设备无法处理。让我们来解决这个问题。

### 注意

我们还存在线程问题，因为错误的图像可能出现在行上。

1.  尽管最好的解决方案是让服务器返回缩略图而不是大图像，但我们并不总能控制这一点，特别是在处理第三方来源时。因此，解决内存问题的一种方法是在`MainAdapter`类中加载位图时为`BitmapFactory Options`设置`inSampleSize`属性，就像我们在前几章的示例中所做的那样。

1.  但是，在这里使用`Picasso`库将更加高效。`Picasso`是一个流行的图像库，将简化我们的流程。除其他功能外，它将在单独的线程中从互联网加载图像，并将其缩小到其容器的大小，这里是适配器布局中的图像视图。

1.  打开`app`文件夹中的`build.gradle`文件，并添加`Picasso`的依赖项：

```kt
dependencies {
    compile fileTree(dir: 'libs', include: ['*.jar'])
    compile 'com.squareup.picasso:picasso:2.3.3'
}
```

1.  保存文件并单击出现的**立即同步**链接。

1.  打开`MainAdapter`类，并用一行代码替换加载图像的线程（以及其中的任何内容）。使用*Alt* + *Enter*快捷键添加`Picasso`导入：

```kt
Picasso.with(getContext()).load(item.imageUrl).resize(80,
  60).into(holder.image);
```

1.  就是这样。`Picasso`将负责下载和调整图像的大小。

1.  现在再次运行应用程序，并随意滚动列表。内存和线程问题都已解决。列表视图可以平滑滚动。

1.  如果查看**Android**面板的**内存**和**CPU**选项卡，您将了解到这样做的区别。

以下屏幕截图提供了**内存**报告：

![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_10.jpg)

以下屏幕截图提供了**CPU**报告：

![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_11.jpg)

我们刚刚修复了我们的应用程序，现在能够显示一大堆糟糕的电影。在下一个教程中，我们将检查应用程序是否存在过度绘制问题。在旧的或性能较差的设备上，可能会出现这些问题。

## 还有更多...

`Picasso`还有一些其他有趣的功能，比如创建圆形图像，旋转图像，或者自动显示错误或占位图像。

`Picasso`的替代方案是`Universal Image Loader`库。

`RetroFit`是一个强烈推荐的用于 API 通信的库。它是 Android 和 Java 的 REST 客户端，可以节省大量时间和头疼。

### 注意

**Android Studio 提示**

想要重构你的代码吗？使用快捷键*Ctrl* + *T*（对于 Windows：*Ctrl* + *Alt* + *Shift* + *T*）来查看你有哪些选项。例如，你可以重命名一个类或方法，或者从一个方法中提取代码。

# 过度绘制问题

你的应用程序的界面需要快速渲染，例如，滚动列表时的交互应该运行顺畅。特别是旧的或低端设备经常很难做到这些。无响应或缓慢的用户界面可能是结果，这通常是由所谓的过度绘制引起的。

过度绘制是指视图上的像素被绘制多次的现象。一个带有另一个背景颜色的视图的彩色背景就是过度绘制的一个例子（像素被绘制两次），但这并不是真正的问题。然而，过度绘制过多会影响应用程序的性能。

## 准备就绪

你需要有一个真实的设备，并且需要完成前一个教程中的`The Bad`应用程序，以演示过度绘制问题，但如果愿意，你也可以检查任何其他应用程序。

## 如何做...

你的设备包含一些有趣的开发者选项。其中之一是**调试 GPU 过度绘制**选项，可以通过以下步骤获得：

1.  在你的设备上，打开**设置**应用程序。

1.  选择**开发者选项**。

### 注意

如果你的设备上没有**开发者选项**项目，你需要先进入**关于设备**，然后点击**版本号**七次。完成后，返回。现在列表中会出现一个名为**开发者选项**的新选项。

1.  找到**调试 GPU 过度绘制**选项并点击它：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_12.jpg)

1.  在弹出的对话框中，选择**显示过度绘制**区域。

1.  现在，你的设备看起来有点像没有相应眼镜的 3D 电影，但实际上显示的是：颜色表示过度绘制的数量，没有颜色表示没有过度绘制（像素只被绘制一次），蓝色表示过度绘制 1 次，绿色表示过度绘制 2 次，浅红色表示过度绘制 3 次，深红色表示过度绘制 4 次甚至更多。

### 提示

最多过度绘制 2 次是可以接受的，所以让我们集中在红色部分。

1.  运行你想要检查的应用程序。在这个教程中，我选择了前一个教程中的`The Bad`应用程序进行检查，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_09_13.jpg)

1.  是的，情况非常糟糕。每个视图都有自己的背景颜色，导致过度绘制。

1.  Android 足够智能，可以减少一些过度绘制的情况，但对于复杂的应用程序，你需要自己解决。当你查看前一个教程中的活动和适配器的布局时，这并不难。

1.  首先，打开`activity_main.xml`布局文件。删除列表视图中的`background`属性，因为它根本没有被使用。同时，也从`RelativeLayout`文件中删除背景属性，因为我不喜欢橙色，至少不适合应用程序。

1.  从`main_text_genre`、`main_text_director`和`main_text_actors`文本视图中删除`background`属性。同时，从它们的父视图中删除`background`属性，即出现在`TableLayout`中的最后一个`TableRow`。

1.  如果重新运行应用程序，应用程序不仅会布局得更好一些，而且你还会注意到过度绘制的迹象减少了。

1.  让我们检查一下是否可以进一步改进。将根部的`FrameLayout`更改为`RelativeLayout`。摆脱`TableLayout`并相对定位文本视图：

```kt
<?xml version="1.0" encoding="utf-8"?><RelativeLayout xmlns:android=
  "http://schemas.android.com/apk/res/android"
    android:orientation="vertical"    
    android:layout_width="match_parent"
    android:background="@android:color/holo_green_light"
    android:padding="8dp"
    android:layout_height="match_parent">
    <ImageView
        android:id="@+id/main_image"android:src="img/ic_media_play"android:layout_marginTop="8dp"android:layout_width="80dp"android:scaleType="fitCenter"android:layout_height="60dp" />
    <TextView android:layout_width="match_parent"android:id="@+id/main_text_title"android:layout_marginTop="8dp"android:layout_toRightOf="@+id/main_image"android:background="@android:color/holo_purple"android:textSize="24sp"android:layout_height="wrap_content"android:textColor="@android:color/white"android:text="Line 1"/>
    <TextView android:layout_width="match_parent"android:id="@+id/main_text_year"android:layout_height="wrap_content"android:layout_toRightOf="@+id/main_image"android:layout_below="@+id/main_text_title"android:background=
         "@android:color/holo_blue_light"android:textSize="20sp"android:layout_marginTop="8dp"android:textColor="@android:color/white"android:text="Line 2"/>
    <TextView android:layout_width="match_parent"android:id="@+id/main_text_genre"android:layout_height="wrap_content"android:layout_toRightOf="@+id/main_image"android:layout_below="@+id/main_text_year"android:textSize="16sp"android:layout_marginTop="8dp"android:textColor="@android:color/white"android:text="Sub  1"/>
    <TextView android:layout_width="match_parent"android:id="@+id/main_text_director"android:layout_height="wrap_content"android:layout_toRightOf="@+id/main_image"android:layout_below="@+id/main_text_genre"android:textSize="16sp"android:layout_marginTop="8dp"android:textColor="@android:color/white"android:text="Sub 2"/>
    <TextView android:layout_width="match_parent"android:id="@+id/main_text_actors"android:layout_height="wrap_content"android:layout_toRightOf="@+id/main_image"android:layout_below="@+id/main_text_director"android:textSize="16sp"android:layout_marginTop="8dp"android:textColor="@android:color/white"android:text="Sub 3"/>
</RelativeLayout>
```

1.  再次运行您的应用程序。它变得越来越好了，不是吗？

1.  要进一步改进您的应用程序，请删除所有`text`属性。它们只是用来检查我们是否在使用`layout_toRightOf`和`layout_below`属性时做对了。

在这个示例中，我们通过优化布局进一步改进了我们的糟糕应用程序。而且，它不再难看。实际上，它变得相当不错。

### 使用哪种布局类型？

使用`RelativeLayout`比`LinearLayout`更有效，但不幸的是，如果，例如，您想要移动或删除另一个视图引用的文本视图，则对开发人员不太友好。

`FrameLayout`要简单得多，但它没有这个问题，而且似乎表现和`RelativeLayout`一样好。

另一方面，它并不打算包含许多子部件。请注意，最终重要的是最小数量的嵌套布局视图，因此您应该选择适合您的需求并且性能最佳的容器。

太棒了！我们的应用程序在所有设备上都运行流畅。我们不再期望出现任何奇怪的错误。

现在让我们将其发送给我们的 Beta 用户，看看他们对此的看法。一旦我们完成最后一章，我们将讨论*临时分发*，我们就会知道了。

## 还有更多...

还有更多有趣的工具，也许您想检查以改进应用程序的质量和性能。

我们之前提到过`Espresso`。`Robotium`是另一个用于 UI 测试的 Android 测试自动化框架。您可以在[`robotium.com`](http://robotium.com)找到它。

## 另请参阅

+   第八章, *提高质量*

+   第十章, *测试您的应用程序的 Beta 版*


# 第十章：测试您的应用程序

您已经尽力确保应用程序的质量和性能。现在是时候将应用程序发布到测试版用户，看看他们对此的看法了。

### 提示

在发布应用程序之前，您应该先查看 Crashlytics。您可以在[`try.crashlytics.com`](https://try.crashlytics.com)找到它。

Crashlytics 可以为您提供实时崩溃报告信息，不仅在测试版测试期间，还在您的应用程序发布到 Play 商店后。迟早，您的应用程序会在您没有测试过的设备上运行，并在其上崩溃。Crashlytics 可以帮助您找到这一原因。

只需下载他们的 SDK，向您的应用程序添加几行代码，然后您就可以开始了。

在将应用程序发布到 Play 商店上向大众公开之前，先分发您的应用程序并进行测试。从他们的反馈中学习并改进您的应用程序。

最后，您可以将这个标志放在您的网站上：

![测试您的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_01.jpg)

在本章中，您将学习以下内容：

+   构建变体

+   运行时权限

+   Play 商店测试版分发

# 介绍

典型的软件发布周期是这样的，尽管不一定必须经过每个阶段：

Alpha -> 封闭测试版 -> 公开测试版 -> 发布。

您可以直接在 Google Play 商店上发布您的应用程序，但至少进行一轮测试是明智的。收集反馈并进行进一步改进可以使您的应用程序变得更好。

我们将看看如何为您的应用程序设置多个不同的风味，以及如何为其定义不同的构建类型。例如，您的发布应用程序很可能会使用不同的 API 端点，而不是您用于调试和测试的端点，至少我希望如此。

您选择的最低 API 级别、所需功能和所请求的权限将影响您的应用程序在 Play 商店中可用的设备数量。此外，我们将预览 Android Marshmallow 提供的运行时权限需要不同的方法。

最后，我们将找出在 Google Play 商店上分发应用程序的测试版或 Alpha 版本需要做什么。

# 构建变体

Android Studio 支持应用程序的不同配置。例如，您的应用程序可能会在调试时使用不同的 API 端点。为此，我们将使用构建类型。

除此之外，您可能会有不同版本的应用程序。一个项目可以有多个定制版本的应用程序。如果这些变化很小，例如只是改变了应用程序的外观，那么使用风味是一个好方法。

构建变体是构建类型和特定风味的组合。接下来的教程将演示如何使用这些。

## 准备工作

对于这个教程，您只需要一个最新版本的 Android Studio。

## 如何做...

我们将构建一个简单的消息应用程序，该应用程序使用不同的构建类型和构建风味：

1.  在 Android Studio 中创建一个新项目，命名为`WhiteLabelMessenger`，在**公司域**字段中输入公司名称，然后单击**确定**按钮。

1.  接下来，选择**手机和平板电脑**，然后单击**下一步**按钮。

1.  选择**空白活动**，然后单击**下一步**按钮。

1.  接受建议的值，然后单击**完成**按钮。

1.  打开`strings.xml`文件并添加一些额外的字符串。它们应该看起来像这样：

```kt
<resources>
    <string name="app_name">WhiteLabelMessenger</string>
    <string name="hello_world">Hello world!</string>
    <string name="action_settings">Settings</string>
    <string name="button_send">SEND YEAH!</string>
    <string name="phone_number">Your phone number</string>
    <string name="yeah">Y-E-A-H</string>
    <string name="really_send_sms">YES</string>
</resources>
```

1.  在`res/drawable`文件夹中创建一个`icon.xml`和一个`background.xml`资源文件。

1.  在`res/drawable`文件夹中，创建一个名为`icon.xml`的新文件。它将绘制一个蓝色的圆圈：

```kt
<?xml version="1.0" encoding="utf-8"?>
<shape    
    android:shape="oval">
    <solid
        android:color="@android:color/holo_blue_bright"/>
    <size
        android:width="120dp"
        android:height="120dp"/>
</shape>
```

1.  在`res/drawable`文件夹中，创建一个名为`background.xml`的新文件。它定义了一个渐变蓝色背景：

```kt
<?xml version="1.0" encoding="utf-8"?>
<selector >
    <item>
        <shape>
            <gradient
                android:angle="90"
                android:startColor="@android:color/holo_blue_light"android:endColor="@android:color/holo_blue_bright"android:type="linear" />
        </shape>
    </item>
</selector>
```

1.  打开`activity_main.xml`文件并修改它，使其看起来像这样：

```kt
<FrameLayout xmlns:android=
  "http://schemas.android.com/apk/res/android"
      android:layout_width="match_parent"
     android:layout_height="match_parent"    android:paddingLeft="@dimen/activity_horizontal_margin"       
     android:paddingRight="@dimen/activity_horizontal_margin"android:paddingTop="@dimen/activity_vertical_margin"android:background="@drawable/background"       
     android:paddingBottom= "@dimen/activity_vertical_margin" 
     tools:context=".MainActivity">
    <EditText
        android:id="@+id/main_edit_phone_number"
        android:layout_marginTop="38dp"
        android:textSize="32sp"
        android:gravity="center"
        android:hint="@string/phone_number"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
    <Button
        android:id="@+id/main_button_send"android:background="@drawable/icon"android:layout_gravity="center"android:layout_width="200dp"android:layout_height="200dp" />
    <TextView
        android:text="@string/button_send"android:textSize="32sp"android:gravity="center"android:layout_gravity="bottom"android:textColor="@android:color/white"android:layout_width="match_parent"android:layout_height="wrap_content" />
</FrameLayout>
```

1.  打开`androidmanifest.xml`文件并添加一个发送短信的权限：

```kt
<uses-permission 
 android:name="android.permission.SEND_SMS"/>
```

1.  修改`MainActivity`文件的`onCreate`方法。您可以按两次*Shift*键来显示搜索面板。在搜索面板上输入`onCreate`，并选择`MainActivity`类的`onCreate`方法：

```kt
findViewById(R.id.main_button_send).setOnClickListener(this);
```

1.  在`MainActivity`类上添加一个点击监听器，并实现`onClick`方法：

```kt
public class MainActivity extends Activity implements View.OnClickListener{
@Override
public void onClick(View v) {
    String phoneNumber = ((EditText)findViewById( 
     R.id.main_edit_phone_number)).getText().toString();
    SmsManager sms = SmsManager.getDefault();
    String message = getString(R.string.yeah);
    if (getString(R.string.really_send_sms)  == "YES"){
     Toast.makeText(this, String.format(
      "TEST Send %s to %s", message, phoneNumber), Toast.LENGTH_SHORT).show();
    }
    else {
      sms.sendTextMessage(phoneNumber, null, message, null, 
       null);

      Toast.makeText(this, String.format(
       "Send %s to %s", message, phoneNumber), Toast.LENGTH_SHORT).show();
    }
}
```

1.  选择`app`文件夹。然后，从**构建**菜单中选择**编辑风味**。

1.  列表中只包含一个 defaultConfig。单击**+**按钮添加一个新的风味。将其命名为`blueFlavor`，并与**defaultConfig**相同的值作为`min sdk version`和`target sdk version`。

1.  对于**application id**字段，使用包名**+**扩展名`.blue`。

1.  为该风味输入**版本代码**和**版本名称**，然后单击**确定**按钮。

1.  为另一个风味重复步骤 14 到 16。将该风味命名为`greenFlavor`。

1.  现在您的`build.gradle`文件应该包含如下风味：

```kt
productFlavors {
    blueFlavor {
        minSdkVersion 21
        applicationId 'packt.com.whitelabelmessenger.blue'targetSdkVersion 21
        versionCode 1
        versionName '1.0'
    }
    greenFlavor {
        minSdkVersion 21
        applicationId 'packt.com.whitelabelmessenger.green'targetSdkVersion 21versionCode 1
        versionName '1.0'
    }
}
```

1.  在**项目**面板中，选择`app`文件夹下的`src`文件夹。然后，创建一个新文件夹，并命名为`blueFlavor`。在该文件夹中，您可以保持与`main`文件夹相同的结构。对于本教程，只需添加一个`res`文件夹，在该文件夹中再添加一个名为`drawable`的文件夹即可。

1.  对`greenFlavor`构建的风味执行相同的操作。项目结构现在如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_02.jpg)

1.  从`/main/res/drawable`文件夹中复制`background.xml`和`icon.xml`文件，并将它们粘贴到`blueFlavor/res/drawable`文件夹中。

1.  为`greenFlavor`重复此操作，并在`greenFlavor/res/drawable`文件夹中打开`background.xml`文件。修改其内容。对于绿色风味，我们将使用渐变绿色：

```kt
<?xml version="1.0" encoding="utf-8"?>
<selector xmlns:android=
  "http://schemas.android.com/apk/res/android">
    <item>
        <shape>
            <gradient
            android:angle="90"
            android:startColor= 
             "@android:color/holo_green_light"                   
            android:endColor=  
             "@android:color/holo_green_dark"
            android:type="linear" />
        </shape>
    </item>
</selector>
```

1.  现在，在同一文件夹中，打开`icon.xml`文件，并将`drawable`文件夹也显示为绿色：

```kt
<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android=
   "http://schemas.android.com/apk/res/android"
     android:shape="oval">
    <solidandroid:color="@android:color/holo_green_dark"/>
    <size
        android:width="120dp"android:height="120dp"/>
</shape>
```

1.  可以使用相同的方法来为调试和发布构建类型使用不同的值（或类或布局）。在`app/src`文件夹中创建一个`debug`文件夹。

1.  在该文件夹中，创建一个`res`文件夹，然后在其中创建一个`values`文件夹。

1.  将`strings.xml`文件从`main/res/values`文件夹复制并粘贴到`debug/res/values`文件夹中。

1.  打开`strings.xml`文件，并修改`really_send_sms`字符串资源：

```kt
<string name="really_send_sms">NO</string>
```

### 提示

当然，为了简单起见，我们将修改字符串资源，而更好的方法当然是使用一个定义不同值的常量类。

### 构建变体

选择`app`文件夹，并从**构建**菜单中选择**选择构建变体**。它将显示如下截图所示的**构建变体**面板：

![构建变体](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_03.jpg)

在**构建变体**中按照以下步骤进行：

1.  选择**greenFlavorDebug**构建变体，并运行应用程序。

1.  如果一切顺利，应用程序将呈现绿色外观，并且表现得好像正在进行调试。

1.  现在将构建变体更改为**blueFlavorDebug**，然后再次运行应用程序。确实，现在它看起来是蓝色的。

### 构建类型

调试和发布构建类型也基本相同；但是，这次不是外观，而是行为或数据（或者端点）发生了变化。

### 注意

发布应用程序需要签名，这是我们将在将应用程序分发到 Play 商店时执行的操作，这在上一篇教程中已经描述过了。

![构建类型](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_04.jpg)

这基本上就是构建变体的全部内容。大多数理想的构建类型和风味只包含少量修改。如果您的应用程序的各种风味之间的差异不仅仅是在布局、可绘制对象或常量值上进行一些微调，那么您将不得不考虑采用不同的方法。

## 还有更多...

Android Studio 还提供了一些其他很棒的功能来完成您的应用程序。其中之一是自动生成技术文档。只需向类或方法添加一些注释，就像这样：

```kt
/*** This is the main activity where all things are happening*/
public class MainActivity extends Activity implements View.OnClickListener{
```

现在，如果您从**工具**菜单中选择**生成 JavaDoc**，并在出现的对话框中定义**输出目录**字段的路径，您只需要点击**确定**按钮，所有文档都将被生成为 HTML 文件。结果将显示在您的浏览器中，如下所示：

![更多内容...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_05.jpg)

### 注意

**Android Studio 提示**

您经常需要返回到代码中的特定位置吗？使用*Cmd* + *F3*（对于 Windows：*F11*）快捷键创建书签。

要显示书签列表并从中选择，请使用快捷键*Cmd* + *F3*（对于 Windows：*Shift* + *F11*）。

# 运行时权限

您的应用程序将针对不同类型的设备取决于功能要求（需要权限）和您所针对的市场（通过明确选择特定国家或提供特定语言的应用程序）的数量。

例如，如果您的应用程序需要前置摄像头和后置摄像头，那么您将针对较少数量的设备，就像您只需要后置摄像头一样。

通常，在安装应用程序时，用户会被要求接受（或拒绝）所有所需的权限，就像在应用程序的`AndroidManifest`文件中定义的那样。

随着 Android 6（Marshmallow）的推出，用户被要求特定权限的方式发生了变化。只有在需要某种类型的权限时，用户才会被提示，以便他可以允许或拒绝该权限。

有了这个机会，应用程序可以解释为什么需要这个权限。之后，整个过程对用户来说就更有意义了。这些所谓的运行时权限需要一种稍微不同的开发方法。

对于这个示例，我们将修改之前发送短信的应用程序。现在，我们需要在用户点击按钮后请求用户的权限，以便发送短信。

## 准备工作

要测试运行时权限，您需要有一个运行 Android 6.0 或更高版本的设备，或者您需要有一个运行 Android Marshmallow 或更高版本的虚拟设备。

还要确保您已经下载了 Android 6.x SDK（API 级别 23 或更高）。

## 操作步骤...

那么，这些运行时权限是什么样的，我们如何处理它们？可以通过以下步骤来检查：

1.  从上一个示例中打开项目。

1.  打开`AndroidManifest`文件，并添加权限（根据新模型）以发送短信：

```kt
<uses-permission-sdk- 
 android:name="android.permission.SEND_SMS"/>
```

1.  在`app`文件夹中打开`build.gradle`文件，并将`compileSdkVersion`的值设置为最新可用版本。还要将每个`minSdkVersion`和`targetSdkVersion`的值更改为`23`或更高。

1.  修改`onClick`方法：

```kt
@Override
public void onClick(View v) {
    String phoneNumber = ((EditText) findViewById( 
     R.id.main_edit_phone_number)).getText().toString();
    String message = getString(R.string.yeah);
    if (Constants.isTestSMS) {
      Toast.makeText(this, String.format(
       "TEST Send %s to %s", message, phoneNumber), 
       Toast.LENGTH_SHORT).show();
    } 
    else {
      if (checkSelfPermission(Manifest.permission.SEND_SMS)   
       != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{  
              Manifest.permission.SEND_SMS},
                 REQUEST_PERMISSION_SEND_SMS);
        }
    }
}
```

1.  添加一个常量值，以便以后我们将知道权限请求的权限结果是指哪个权限请求：

```kt
private final int REQUEST_PERMISSION_SEND_SMS = 1;
```

1.  实现`sendSms`方法。我们将使用`SmsManager`方法将`Y-E-A-H`文本发送到用户输入的电话号码。一旦消息发送成功，将显示一个 toast：

```kt
private void sendSms(){
    String phoneNumber = ((EditText) findViewById( 
     R.id.main_edit_phone_number)).getText().toString();
    String message = getString(R.string.yeah);
    SmsManager sms = SmsManager.getDefault();
    sms.sendTextMessage(phoneNumber, null, 
     getString(R.string.yeah), null, null);
    Toast.makeText(this, String.format("Send %s to %s", getString(R.string.yeah), phoneNumber), Toast.LENGTH_SHORT).show();
}
```

1.  最后，实现`onRequestPermissionsResult`方法。如果授予的权限是短信权限，则调用`sendSms`方法。如果权限被拒绝，则会显示一个 toast，并且**发送**按钮和输入电话号码的编辑文本将被禁用：

```kt
@Override
public void onRequestPermissionsResult(int requestCode,  String permissions[], int[] grantResults) {
    switch (requestCode) {
        case REQUEST_PERMISSION_SEND_SMS: {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                sendSms();
            }
            else {                
              findViewById(
               R.id.main_edit_phone_number).setEnabled(false); 
              findViewById(  
               R.id.main_button_send).setEnabled(false);
                Toast.makeText(this, 
                 getString(R.string.no_sms_permission), Toast.LENGTH_SHORT).show();
            }
            return;
        }
    }
}
```

1.  运行您的应用程序。使用运行 Android 6.0 或更高版本的设备，或者创建一个运行 API 级别 23 或更高版本的虚拟设备。

1.  现在，发送短信的权限不会被事先要求（也就是说，如果用户安装了应用程序）。相反，一旦您点击**发送**按钮，就会弹出一个请求权限的对话框。

1.  如果您同意请求权限，短信将被发送。如果您拒绝了请求的权限，编辑框和按钮将被禁用，并且将显示一个 toast 以提供反馈：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_06.jpg)

这个示例演示了运行时权限的基本概念。

## 更多内容...

要了解何时以及如何请求权限，或者何时以及如何提供有关不可用特定功能的反馈意见，您可以在[`www.google.com/design/spec/patterns/permissions.html`](https://www.google.com/design/spec/patterns/permissions.html)上查看 Google 的指南。

### 注意

**Android Studio 提示**

您可以轻松地从变得太大的方法中提取代码。只需标记您想要移动的代码，然后使用快捷键*Cmd* + *Alt* + *M*（对于 Windows：*Ctrl* + *Alt* + *M*）。

# Play 商店 beta 分发

好了，我们将把我们的应用程序上传到 Play 商店作为 beta 分发。很激动人心，不是吗？

## 准备工作

对于这个食谱，我们将使用第一个食谱中的应用程序；尽管如此，任何您认为已准备好进行 beta 发布的应用程序都可以。

确保您也有一些艺术作品，例如图标和截图。别担心，对于这个食谱，您也可以从<[www.packtpub.com](http://www.packtpub.com)>下载这些项目。此外，考虑您应用程序的元数据，例如标题、描述和类别。

最重要的是您必须拥有开发者帐户，并且可以访问 Google Play 开发者控制台。如果您没有帐户，您需要首先通过[`developer.android.com/distribute/googleplay/start.html`](http://developer.android.com/distribute/googleplay/start.html)注册。

## 如何做...

将您的应用程序放入 Play 商店并不难。只是需要一些时间来正确设置事物：

1.  登录到您的**Google Play 开发者控制台**网页，或者如果需要的话，首先注册。

1.  在仪表板上，点击**添加新应用程序**按钮。

1.  在对话框中，输入应用程序的**标题**“蓝色信使”，然后点击**立即上传 APK**按钮。

1.  您会注意到**production**、**beta**和**alpha**选项卡。理想情况下，您应该从 alpha 测试开始，但出于演示目的，我们将立即选择**beta**选项卡。在那里，将显示**将第一个 APK 上传到 beta**按钮。点击该按钮。

1.  在 Android Studio 中，打开我们为第一个（或第二个）食谱创建的应用程序，然后从**构建**菜单中选择**生成已签名的 APK**选项。

1.  选择`app`模块，然后点击**下一步**按钮。

1.  输入**密钥库的路径**。如果没有，请点击**创建新...**按钮，找到一个适合您的密钥库文件（带有`.jks`扩展名）的好地方。为其输入一个**密码**，重复密码，并输入**名字**的合适值。然后，点击**确定**按钮。

1.  输入**密钥库密码**，创建一个新的**密钥别名**，并将其命名为`whitelabelmessenger`。为密钥输入一个**密码**，然后点击**下一步**按钮。

1.  如果需要，输入**主密码**，然后点击**确定**按钮。

1.  如果需要，修改**目标路径**，然后选择**构建类型**和**风味**。选择**发布**和**blueFlavor**，然后点击**确定**按钮。

1.  一个新的对话框通知我们，如果一切顺利，已成功创建了一个新的已签名 APK。点击**在 Finder 中显示**（或者在 Windows 中使用 Windows 资源管理器找到）按钮，以查看刚刚创建的 APK 文件。

1.  在浏览器中上传此 APK 文件。一旦 APK 文件上传完成，版本将显示在**beta**选项卡上；您可以选择测试方法并查看受支持设备的数量，这将取决于您选择的 API 级别以及带有短信权限的必需功能（例如，这将立即排除许多平板电脑）。

1.  对于测试方法，点击**设置封闭式 beta 测试**按钮。

1.  点击**创建列表**按钮创建一个列表。给列表取一个名字，例如**内部测试**，然后添加测试人员的电子邮件地址（或者只是为了练习，输入您自己的）。完成后，点击**保存**按钮。

1.  将您自己的电子邮件地址输入为**反馈渠道**，然后点击**保存草稿**按钮。

1.  尽管我们尚未在商店上发布任何内容，但您需要为**商店列表**部分输入一些值，这是您可以从网页左侧的菜单中选择的选项：![如何做…](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_07.jpg)

1.  输入标题、简短和长描述。还要添加两张截图、一个高分辨率图标和一个特色图像。您可以从<[www.packtpub.com](http://www.packtpub.com)>下载这些资源，或者您可以通过从您的应用中截取截图并使用某种绘图程序进行一些有趣的操作，以使它们具有正确的宽度和高度。

1.  在**分类**中，选择**应用程序**作为**应用程序类型**，并选择**社交**或**通讯**作为**类别**。

1.  输入您的**联系方式**，并选择**目前不提交隐私政策**（除非您确实希望这样做）。

1.  点击**保存草稿**按钮，然后从屏幕左侧的菜单中选择**内容评级**部分，继续进行。

### 为您的应用评分

点击**继续**按钮，输入您的**电子邮件地址**，并回答有关您的应用是否具有任何暴力、色情或其他潜在危险内容或功能的问题。最后，点击**保存问卷**按钮：

1.  现在，您可以点击**计算评级**按钮。之后将显示您的评级。点击**应用评级**按钮，然后您就完成了。

1.  接下来是**定价和分发**部分。从页面左侧的菜单中选择此选项。

1.  通过点击**免费**按钮，使其成为免费应用，并**选择所有国家**（或者如果您愿意，可以指定特定国家）。之后，点击**保存草稿**按钮。

1.  到目前为止，**发布应用**按钮应该已经启用。点击它。如果它没有启用，您可以点击**我无法发布？**链接，找出缺少哪些信息。

1.  在这里，“发布”这个词有点令人困惑。实际上，在这种情况下，它意味着该应用将被发布给您刚刚创建的测试用户名单上的用户。不用担心。在您将应用程序推广到生产环境之前，Play 商店中将不会有任何内容，尽管“发布”这个词似乎暗示了这一点。

1.  当您的应用状态显示为**待发布**时，您可以调查一些其他选项，比如您的应用支持的设备列表、所需功能和权限以及用于分析目的的选项，包括功能分割测试（A/B 测试）。

### 休息一下

**待发布**状态可能需要几个小时（甚至更长时间），因为自 2015 年 4 月以来，谷歌宣布将事先审查应用程序（以半手动半自动的方式），即使是 alpha 和 beta 版本的分发也是如此。

1.  吃一个棉花糖，喝点咖啡，或者在公园里散散步。几个小时后回来检查您的应用状态是否已更改为**已发布**。可能需要一些时间，但会成功的。

### 注意

您的测试人员可能需要更改其（安全）设置，以**允许在 Google Play 商店之外安装应用程序**。

1.  还有一些其他看起来令人困惑的事情。在包名称后面，会有一个链接，上面写着**在 Play 商店中查看…**，还有一个提示说 alpha 和 beta 应用程序不会在 Play 商店中列出。

1.  在网页左侧的菜单中点击**APK**项目。通过链接，您将在**Beta**选项卡上找到**Opt In Url**，您的测试用户可以通过该链接下载并安装 beta 应用程序：![休息一下](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_10_08.jpg)

太棒了！您的第一个 beta 分发已经准备好进行测试。您可能需要多次迭代才能做到完美，或者也许只需要一个 beta 版本就足以发现您的应用已经准备好进入**Play 商店**。

要在 Play 商店上发布你的应用，点击**推广到生产**按钮，如果你敢的话…

就到这里吧。还有很多关于 Android 开发的东西要讲和学习，比如服务、Android Pay、**近场通讯**（NFC）和蓝牙等等；然而，通过阅读这本书，你已经看到了 Android Studio IDE 的大部分元素，这也是我们的目标。

就是这样了。谢谢你的阅读，祝你编码愉快！

## 还有更多…

你应该意识到，除了技术，方法论同样重要。开发一个不仅在技术上完美，而且有很多用户对你的应用和其流程、可用性和外观都非常满意，给你应得的五星评价的应用是很难的。

我假设你不想花几个月甚至几年的时间开发一个应用，最后发现其实没有人在乎。在早期阶段找出是什么让人们真正想使用你的应用，你应该考虑精益创业方法论来开发你的应用。

**构建-测量-学习**

**精益创业**方法论是一种开发企业和产品（或服务）的方法。其理念是基于假设的实验、验证学习和迭代产品发布会导致更短的产品开发周期。

精益创业方法论的最重要的关键元素是：

+   **最小可行产品**（MVP）

+   分割测试和可操作指标

+   持续部署

简而言之，MVP 是产品的一个版本，需要最小的努力来测试特定的假设。

要了解更多关于精益创业方法论的信息，可以查看网站[`theleanstartup.com`](http://theleanstartup.com)，阅读 Eric Ries 的书，或者从[`www.leanstartupcircle.com`](http://www.leanstartupcircle.com)找到一个靠近你的精益创业活动。

**Play 商店开发者控制台**提供了分割测试和测量应用程序使用情况的选项。谷歌分析可以帮助你做到这一点，因为这是获得可操作指标的最简单方法，你需要收集这些指标以便通过学习改进你的应用程序。

**持续部署**很好地融入了精益创业方法论。它可以提高应用程序开发的质量和速度。

你可能会想知道持续部署是什么。完全解释这个概念需要另一本书，但这里是对持续集成和持续交付的简要介绍，如果结合起来，就是持续部署的内容。

**持续集成**（CI）是开发人员提交他们的更改并将结果合并到源代码存储库的过程。构建服务器观察代码存储库的更改，拉取和编译代码。服务器还运行自动化测试。

**持续交付**是自动创建可部署版本的过程，例如，通过在 Play 商店发布 alpha 或 beta 应用。因此，提交和验证的代码始终处于可部署状态是很重要的。

设置持续部署需要一些前期工作，但最终会导致更小更快的开发周期。

对于 Android 应用程序的持续部署，`Jenkins`和`TeamCity`都是合适的。`Teamcity`经常被推荐，并且使用插件可以与 Android Studio 集成。

要了解如何设置`TeamCity`服务器或找到更多信息，你可以查看 Packt Publishing 的网站，那里有一些很好的书来解释持续集成和`TeamCity`的概念。
