# 如何使用 Kotlin 构建安卓应用（七）

> 原文：[`zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295`](https://zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：架构模式

概述

本章将介绍您可以用于 Android 项目的架构模式。它涵盖了使用**MVVM**（模型-视图-ViewModel）模式，添加 ViewModels 以及使用数据绑定。您还将了解使用存储库模式进行数据缓存和使用 WorkManager 进行数据检索和存储的调度。

在本章结束时，您将能够使用 MVVM 和数据绑定来构建 Android 项目。您还将能够使用 Room 库的存储库模式缓存数据和使用 WorkManager 在预定的时间间隔内获取和保存数据。

# 介绍

在上一章中，您了解了如何使用 RxJava 和协程进行后台操作和数据处理。现在，您将学习架构模式，以便改进您的应用程序。

在开发 Android 应用程序时，您可能倾向于在活动或片段中编写大部分代码（包括业务逻辑）。这将使您的项目难以测试和维护。随着项目的增长和变得更加复杂，困难也会增加。您可以通过架构模式改进您的项目。

架构模式是设计和开发应用程序部分的通用解决方案，特别是对于大型应用程序。有一些架构模式可以用来将项目结构化为不同的层（表示层、**用户界面**（UI）层和数据层）或功能（观察者/可观察者）。通过架构模式，您可以以更容易开发、测试和维护的方式组织代码。

对于 Android 开发，常用的模式包括**MVC**（模型-视图-控制器）、**MVP**（模型-视图-表示器）和 MVVM。谷歌推荐的架构模式是 MVVM，本章将对此进行讨论。您还将了解数据绑定、使用 Room 库的存储库模式以及 WorkManager。

让我们开始 MVVM 架构模式。

# MVVM

MVVM 允许您将 UI 和业务逻辑分开。当您需要重新设计 UI 或更新模型/业务逻辑时，您只需触及相关组件，而不影响应用程序的其他组件。这将使您更容易添加新功能并测试现有代码。MVVM 在创建使用大量数据和视图的大型应用程序时也很有用。

使用 MVVM 架构模式，您的应用程序将分为三个组件：

+   **模型**：代表数据层

+   **视图**：显示数据的用户界面

+   将`Model`提供给`View`

通过以下图表更好地理解 MVVM 架构模式：

![图 14.1：MVVM 架构模式](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_14_01.jpg)

图 14.1：MVVM 架构模式

模型包含应用程序的数据和业务逻辑。在 MVVM 中，用户看到并与之交互的活动、片段和布局是视图。视图只处理应用程序的外观。它们让 ViewModel 知道用户的操作（例如打开活动或点击按钮）。

ViewModel 链接视图和模型。ViewModel 从模型获取数据并将其转换为视图中的显示。视图订阅 ViewModel，并在值更改时更新 UI。

您可以使用 Jetpack 的 ViewModel 为应用程序创建 ViewModel 类。Jetpack 的 ViewModel 管理其自己的生命周期，因此您无需自行处理。

您可以通过在`app/build.gradle`文件的依赖项中添加以下代码来将 ViewModel 添加到您的项目中：

```kt
implementation 'androidx.lifecycle:lifecycle-viewmodel-ktx:2.2.0'
```

例如，如果您正在开发一个显示电影的应用程序，您可以拥有一个`MovieViewModel`。这个 ViewModel 将有一个函数，用于获取电影列表：

```kt
class MovieViewModel : ViewModel() {
    private val movies: MutableLiveData<List<Movie>>
    fun getMovies(): LiveData<List<Movie>> { ... }
    ...
}
```

在您的活动中，您可以使用`ViewModelProvider`创建一个 ViewModel：

```kt
class MainActivity : AppCompatActivity() {
    private val movieViewModel by lazy {
        ViewModelProvider(this).get(MovieViewModel::class.java)
    }
    ...
}
```

然后，你可以订阅 ViewModel 中的`getMovies`函数，并在电影列表发生变化时自动更新 UI 中的列表：

```kt
override fun onCreate(savedInstanceState: Bundle?) {
    ...
    movieViewModel.getMovies().observe(this, Observer { popularMovies ->
        movieAdapter.addMovies(popularMovies)
    })
    ...
}
```

当 ViewModel 中的值发生变化时，视图会收到通知。你还可以使用数据绑定将视图与 ViewModel 中的数据连接起来。你将在下一节中学到更多关于数据绑定的知识。

# 数据绑定

数据绑定将布局中的视图与来自 ViewModel 等来源的数据进行绑定。不需要添加代码来查找布局文件中的视图，并在 ViewModel 的值改变时更新它们，数据绑定可以自动处理这些。

要在 Android 项目中使用数据绑定，你应该在`app/build.gradle`文件的`android`块中添加以下内容：

```kt
buildFeatures {
    dataBinding true
}
```

在布局文件中，你必须用`layout`标签包裹根元素。在`layout`标签内，你需要定义要绑定到该布局文件的数据的`data`元素：

```kt
<layout xmlns:android="http://schemas.android.com/apk/res/android">
    <data>
        <variable name="movie" type="com.example.model.Movie"/>
    </data>
    <ConstraintLayout ... />
</layout>
```

电影布局变量代表将在布局中显示的`com.example.model.Movie`类。要将属性设置为数据模型中的字段，你需要使用`@{}`语法。例如，要将电影的标题作为`TextView`的文本值，你可以使用以下内容：

```kt
<TextView
    ...
    android:text="@{movie.title}"/>
```

你还需要更改你的活动文件。如果你的布局文件名为`activity_movies.xml`，数据绑定库将在项目的构建文件中生成一个名为`ActivityMainBinding`的绑定类。在活动中，你可以用以下内容替换`setContentView(R.layout.activity_movies)`这一行：

```kt
val binding: ActivityMoviesBinding = DataBindingUtil.setContentView(this,   R.layout.activity_movies)
```

你还可以使用绑定类的`inflate`方法或`DataBindingUtil`类：

```kt
val binding: ActivityMoviesBinding =   ActivityMoviesBinding.inflate(getLayoutInflater())
```

然后，你可以将`movie`实例绑定到布局中名为`movie`的布局变量中：

```kt
val movieToDisplay = ...
binding.movie = movieToDisplay
```

如果你将`LiveData`作为要绑定到布局的项目，你需要设置绑定变量的`lifeCycleOwner`。`lifeCycleOwner`指定了`LiveData`对象的范围。你可以使用活动作为绑定类的`lifeCycleOwner`：

```kt
binding.lifeCycleOwner = this
```

有了这个，当 ViewModel 中的`LiveData`的值改变时，视图将自动更新为新的值。

你可以使用`android:text="@{movie.title}"`在 TextView 中设置电影标题。数据绑定库有默认的绑定适配器来处理`android:text`属性的绑定。有时，没有默认的属性可供使用。你可以创建自己的绑定适配器。例如，如果你想要为`RecyclerView`绑定电影列表，你可以创建一个自定义的`BindingAdapter`：

```kt
@BindingAdapter("list")
fun bindMovies(view: RecyclerView, movies: List<Movie>?) {
    val adapter = view.adapter as MovieAdapter
    adapter.addMovies(movies ?: emptyList())
}
```

这将允许你为`RecyclerView`添加一个`app:list`属性，接受一个电影列表：

```kt
app:list="@{movies}"
```

让我们尝试在 Android 项目中实现数据绑定。

## 练习 14.01：在 Android 项目中使用数据绑定

在上一章中，你开发了一个使用电影数据库 API 显示热门电影的应用程序。在本章中，你将使用 MVVM 改进该应用程序。你可以使用上一章的 Popular Movies 项目，或者复制一个。在这个练习中，你将添加数据绑定，将 ViewModel 中的电影列表绑定到 UI 上：

1.  在 Android Studio 中打开`Popular Movies`项目。

1.  打开`app/build.gradle`文件，并在`android`块中添加以下内容：

```kt
buildFeatures {
    dataBinding true
}
```

这样就可以为你的应用启用数据绑定。

1.  在`app/build.gradle`文件的插件块末尾添加`kotlin-kapt`插件：

```kt
plugins {
    ...
    id 'kotlin-kapt'
}
```

kotlin-kapt 插件是 Kotlin 注解处理工具，用于使用数据绑定。

1.  创建一个名为`RecyclerViewBinding`的新文件，其中包含`RecyclerView`列表的绑定适配器：

```kt
@BindingAdapter("list")
fun bindMovies(view: RecyclerView, movies: List<Movie>?) {
    val adapter = view.adapter as MovieAdapter
    adapter.addMovies(movies ?: emptyList())
}
```

这将允许你为`RecyclerView`添加一个`app:list`属性，你可以将要显示的电影列表传递给它。电影列表将被设置到适配器中，更新 UI 中的`RecyclerView`。

1.  打开`activity_main.xml`文件，并将所有内容包裹在`layout`标签内：

```kt
<layout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools">
    <androidx.constraintlayout.widget.ConstraintLayout
        ... >
    </androidx.constraintlayout.widget.ConstraintLayout>
</layout>
```

有了这个，数据绑定库将能够为这个布局生成一个绑定类。

1.  在`layout`标签内，在`ConstraintLayout`标签之前，添加一个带有`viewModel`变量的数据元素：

```kt
<data>
    <variable
        name="viewModel"
        type="com.example.popularmovies.MovieViewModel" />
</data>
```

这将创建一个与您的`MovieViewModel`类对应的`viewModel`布局变量。

1.  在`RecyclerView`中，使用`app:list`添加要显示的列表：

```kt
app:list="@{viewModel.popularMovies}"
```

从`MovieViewModel.getPopularMovies`的`LiveData`将作为`RecyclerView`的电影列表传递。

1.  打开`MainActivity`。在`onCreate`函数中，用以下内容替换`setContentView`行：

```kt
val binding: ActivityMainBinding =   DataBindingUtil.setContentView(this, R.layout.activity_main)
```

这将设置要使用的布局文件并创建一个绑定对象。

1.  用以下内容替换`movieViewModel`观察者：

```kt
binding.viewModel = movieViewModel
binding.lifecycleOwner = this
```

这将`movieViewModel`绑定到`activity_main.xml`文件中的`viewModel`布局变量。

1.  运行应用程序。它应该像往常一样工作，显示流行电影的列表，点击其中一个将打开所选电影的详细信息：

![图 14.2：按标题排序的今年热门电影的主屏幕（左）和有关所选电影的详细信息的详细屏幕（右）](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_14_02.jpg)

图 14.2：按标题排序的今年热门电影的主屏幕（左）和有关所选电影的详细信息的详细屏幕（右）

在这个练习中，您已经在 Android 项目上使用了数据绑定。

数据绑定将视图链接到 ViewModel。ViewModel 从模型中检索数据。您可以使用 Retrofit 和 Moshi 等一些库来获取数据，您将在下一节中了解更多信息。

# Retrofit 和 Moshi

连接到远程网络时，您可以使用 Retrofit。Retrofit 是一个 HTTP 客户端，可以轻松实现创建请求并从后端服务器检索响应。

您可以通过将以下代码添加到您的`app/build.gradle`文件的依赖项中，将 Retrofit 添加到您的项目中：

```kt
implementation 'com.squareup.retrofit2:retrofit:2.9.0'
```

然后，您可以使用 Moshi 将 Retrofit 的 JSON 响应转换为 Java 对象。例如，您可以将获取电影列表的 JSON 字符串响应转换为`ListofMovie`对象，以便在应用程序中显示和存储。

您可以通过将以下代码添加到您的`app/build.gradle`文件的依赖项中，将 Moshi Converter 添加到您的项目中：

```kt
implementation 'com.squareup.retrofit2:converter-moshi:2.9.0'
```

在您的 Retrofit 构建器代码中，您可以调用`addConverterFactory`并传递`MoshiConverterFactory`：

```kt
Retrofit.Builder()
    ...
    .addConverterFactory(MoshiConverterFactory.create())
    ...
```

您可以从 ViewModel 中调用数据层。为了减少其复杂性，您可以使用存储库模式来加载和缓存数据。您将在下一节中了解到这一点。

# 存储库模式

ViewModel 不应直接调用服务来获取和存储数据，而应将该任务委托给另一个组件，例如存储库。

使用存储库模式，您可以将处理数据层的 ViewModel 中的代码移动到一个单独的类中。这减少了 ViewModel 的复杂性，使其更易于维护和测试。存储库将管理从哪里获取和存储数据，就像使用本地数据库或网络服务获取或存储数据一样：

![图 14.3：具有存储库模式的 ViewModel](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_14_03.jpg)

图 14.3：具有存储库模式的 ViewModel

在 ViewModel 中，您可以添加一个存储库属性：

```kt
class MovieViewModel(val repository: MovieRepository): ViewModel() {
... 
}
```

ViewModel 将从存储库获取电影，或者它可以监听它们。它将不知道您实际从哪里获取列表。

您可以创建一个存储库接口，连接到数据源，例如以下示例：

```kt
interface MovieRepository { 
    fun getMovies(): List<Movie>
}
```

`MovieRepository`接口具有一个`getMovies`函数，您的存储库实现类将覆盖该函数以从数据源获取电影。您还可以拥有一个单一的存储库类，该类处理从本地数据库或远程端点获取数据：

当将本地数据库用作存储库的数据源时，您可以使用 Room 库，它可以让您更轻松地使用 SQLite 数据库，编写更少的代码，并在查询时进行编译时检查。

您可以通过将以下代码添加到`app/build.gradle`文件的依赖项中来将 Room 添加到您的项目中：

```kt
implementation 'androidx.room:room-runtime:2.2.5'
implementation 'androidx.room:room-ktx:2.2.5'
kapt 'androidx.room:room-compiler:2.2.5'
```

让我们尝试向 Android 项目添加带有 Room 的存储库模式。

## 练习 14.02：在 Android 项目中使用带有 Room 的存储库

在上一个练习中，您已经在流行电影项目中添加了数据绑定。在这个练习中，您将使用存储库模式更新应用程序。

打开应用程序时，它会从网络获取电影列表。这需要一段时间。每次获取数据时，您都将将这些数据缓存在本地数据库中。用户下次打开应用程序时，应用程序将立即在屏幕上显示来自数据库的电影列表。您将使用 Room 进行数据缓存：

1.  打开您在上一个练习中使用的`Popular Movies`项目。

1.  打开`app/build.gradle`文件并添加 Room 库的依赖项：

```kt
implementation 'androidx.room:room-runtime:2.2.5'
implementation 'androidx.room:room-ktx:2.2.5'
kapt 'androidx.room:room-compiler:2.2.5'
```

1.  打开`Movie`类并为其添加一个`Entity`注解：

```kt
@Entity(tableName = "movies",  primaryKeys = [("id")])
data class Movie( ... )
```

`Entity`注解将为电影列表创建一个名为`movies`的表。它还将`id`设置为表的主键。

1.  创建一个名为`com.example.popularmovies.database`的新包。为访问`movies`表创建一个`MovieDao`数据访问对象：

```kt
@Dao
interface MovieDao {
@Insert(onConflict = OnConflictStrategy.REPLACE)
fun addMovies(movies: List<Movie>)
@Query("SELECT * FROM movies")
fun getMovies(): List<Movie>
}
```

该类包含一个用于将电影列表添加到数据库的函数，另一个用于从数据库中获取所有电影的函数。

1.  在`com.example.popularmovies.database`包中创建一个`MovieDatabase`类：

```kt
@Database(entities = [Movie::class], version = 1)
abstract class MovieDatabase : RoomDatabase() {
    abstract fun movieDao(): MovieDao
    companion object {
        @Volatile
        private var instance: MovieDatabase? = null
        fun getInstance(context: Context): MovieDatabase {
            return instance ?: synchronized(this) {
                instance ?: buildDatabase(context).also {                   instance = it                     }
            }
        }
        private fun buildDatabase(context: Context): MovieDatabase {
            return Room.databaseBuilder(context,               MovieDatabase::class.java, "movie-db")
                .build()
        }
    }
}
```

该数据库的版本为 1，有一个名为`Movie`的实体和用于电影的数据访问对象。它还有一个`getInstance`函数来生成数据库的实例。

1.  使用构造函数更新`MovieRepository`类的`movieDatabase`：

```kt
class MovieRepository(private val movieService: MovieService,   private val movieDatabase: MovieDatabase) { ... }
```

1.  更新`fetchMovies`函数：

```kt
suspend fun fetchMovies() {
    val movieDao: MovieDao = movieDatabase.movieDao()
    var moviesFetched = movieDao.getMovies()
    if (moviesFetched.isEmpty()) {
        try {
            val popularMovies = movieService.getPopularMovies(apiKey)
            moviesFetched = popularMovies.results
            movieDao.addMovies(moviesFetched)
        } catch (exception: Exception) {
            errorLiveData.postValue("An error occurred:               ${exception.message}")
        }
    }
    movieLiveData.postValue(moviesFetched)
}
```

它将从数据库中获取电影。如果尚未保存任何内容，它将从网络端点检索列表，然后保存。

1.  打开`MovieApplication`并在`onCreate`函数中，用以下内容替换`movieRepository`的初始化：

```kt
val movieDatabase = MovieDatabase.getInstance(applicationContext)
movieRepository = MovieRepository(movieService, movieDatabase)
```

1.  运行应用程序。它将显示流行电影的列表，单击其中一个将打开所选电影的详细信息。如果关闭移动数据或断开无线网络连接，它仍将显示电影列表，该列表现在已缓存在数据库中：

![图 14.4：使用带有 Room 的流行电影应用程序的存储库](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_14_04.jpg)

图 14.4：使用带有 Room 的流行电影应用程序的存储库

在这个练习中，您通过将数据的加载和存储移到存储库中来改进了应用程序。您还使用了 Room 来缓存数据。

存储库从数据源获取数据。如果数据库中尚未存储数据，应用程序将调用网络请求数据。这可能需要一段时间。您可以通过在预定时间预取数据来改善用户体验，这样用户下次打开应用程序时，他们将立即看到更新的内容。您可以使用我们将在下一节中讨论的 WorkManager 来实现这一点。

# WorkManager

WorkManager 是一个 Jetpack 库，用于延迟执行并根据您设置的约束条件运行后台操作。它非常适合执行必须运行但可以稍后或定期运行的操作，无论应用程序是否正在运行。

您可以使用 WorkManager 定期运行任务，例如从网络获取数据并将其存储在数据库中。即使应用程序已关闭或设备重新启动，WorkManager 也会运行任务。这将使您的数据库与后端保持最新。

您可以通过将以下代码添加到`app/build.gradle`文件的依赖项中来将 WorkManager 添加到您的项目中：

```kt
implementation 'androidx.work:work-runtime:2.4.0'
```

WorkManager 可以调用存储库从本地数据库或网络服务器获取和存储数据。

让我们尝试向 Android 项目添加 WorkManager。

## 练习 14.03：向 Android 项目添加 WorkManager

在上一个练习中，您使用 Room 添加了存储库模式以将数据缓存到本地数据库中。该应用现在可以从数据库中获取数据，而不是从网络获取。现在，您将添加 WorkManager 以安排定期从服务器获取数据并将其保存到数据库的任务：

1.  打开您在上一个练习中使用的`Popular Movies`项目。

1.  打开`app/build.gradle`文件并添加 WorkManager 库的依赖项：

```kt
implementation 'androidx.work:work-runtime:2.4.0'
```

这将允许您向应用程序添加 WorkManager 工作程序。

1.  打开`MovieRepository`并添加一个挂起函数，用于使用 The Movie Database 的 apiKey 从网络获取电影并将其保存到数据库中：

```kt
suspend fun fetchMoviesFromNetwork() {
    val movieDao: MovieDao = movieDatabase.movieDao()
    try {
        val popularMovies = movieService.getPopularMovies(apiKey)
        val moviesFetched = popularMovies.results
        movieDao.addMovies(moviesFetched)
    } catch (exception: Exception) {
        errorLiveData.postValue("An error occurred:           ${exception.message}")
    }
}
```

这将是`Worker`类调用的函数，该类将运行以获取和保存电影。

1.  创建`MovieWorker`类：

```kt
class MovieWorker(private val context: Context,   params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val movieRepository =           (context as MovieApplication).movieRepository
        CoroutineScope(Dispatchers.IO).launch {
            movieRepository.fetchMoviesFromNetwork()
        }
        return Result.success()
    }
}
```

1.  打开`MovieApplication`，并在`onCreate`函数的末尾，安排`MovieWorker`以检索并保存电影：

```kt
override fun onCreate() {
    ...
    val constraints =
        Constraints.Builder().setRequiredNetworkType(          NetworkType.CONNECTED).build()
    val workRequest = PeriodicWorkRequest
        .Builder(MovieWorker::class.java, 1, TimeUnit.HOURS)
        .setConstraints(constraints)
        .addTag("movie-work")
        .build()
    WorkManager.getInstance(applicationContext).enqueue(workRequest)
}
```

当设备连接到网络时，这将安排`MovieWorker`每小时运行。`MovieWorker`将从网络获取电影列表并将其保存到本地数据库。

1.  运行应用程序。关闭它并确保设备已连接到互联网。一个多小时后，再次打开应用程序并检查显示的电影列表是否已更新。如果没有，请几个小时后再试一次。即使应用程序已关闭，显示的电影列表也会定期更新，大约每小时更新一次。

![图 14.5：Popular Movies 应用程序使用 WorkManager 更新其列表](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_04.jpg)

图 14.5：Popular Movies 应用程序使用 WorkManager 更新其列表

在本练习中，您向应用程序添加了 WorkManager，以自动使用从网络检索的电影列表更新数据库。

## 活动 14.01：重新审视电视指南应用程序

在上一章中，您开发了一个可以显示正在播出的电视节目列表的应用程序。该应用程序有两个屏幕：主屏幕和详细信息屏幕。在主屏幕上，有一个电视节目列表。单击电视节目时，将显示详细信息屏幕，并显示所选节目的详细信息。

运行应用程序时，显示节目列表需要一段时间。更新应用程序以缓存列表，以便在打开应用程序时立即显示。此外，通过使用 MVVM 与数据绑定并添加 WorkManager 来改进应用程序。

您可以使用上一章中使用的电视指南应用程序，也可以从 GitHub 存储库中下载。以下步骤将帮助您完成此活动：

1.  在 Android Studio 中打开电视指南应用程序。打开`app/build.gradle`文件并添加`kotlin-kapt`插件，数据绑定依赖项以及 Room 和 WorkManager 的依赖项。

1.  为`RecyclerView`创建一个绑定适配器类。

1.  在`activity_main.xml`中，将所有内容包装在`layout`标签内。

1.  在`layout`标签内并在`ConstraintLayout`标签之前，添加一个包含 ViewModel 变量的数据元素。

1.  在`RecyclerView`中，使用`app:list`添加要显示的列表。

1.  在`MainActivity`中，用`DataBindingUtil.setContentView`函数替换`setContentView`行。

1.  用数据绑定代码替换`TVShowViewModel`中的观察者。

1.  在`TVShow`类中添加一个`Entity`注解。

1.  创建一个`TVDao`数据访问对象，用于访问电视节目表。

1.  创建一个`TVDatabase`类。

1.  使用`tvDatabase`构造函数更新`TVShowRepository`。

1.  更新`fetchTVShows`函数以从本地数据库获取电视节目。如果还没有数据，从端点检索列表并将其保存在数据库中。

1.  创建`TVShowWorker`类。

1.  打开`TVApplication`文件。在`onCreate`中，安排`TVShowWorker`以检索并保存节目。

1.  运行你的应用程序。应用程序将显示一个电视节目列表。点击电视节目将打开显示电影详情的详情活动。主屏幕和详情屏幕将类似于*图 14.6*：

![图 14.6：TV Guide 应用的主屏幕和详情屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_13_11.jpg)

图 14.6：TV Guide 应用的主屏幕和详情屏幕

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 总结

本章重点介绍了 Android 的架构模式。您从 MVVM 架构模式开始。您学习了它的三个组件：模型、视图和视图模型。您还使用数据绑定将视图与视图模型链接起来。

接下来，您了解了存储库模式如何用于缓存数据。然后，您了解了 WorkManager 以及如何安排任务，例如从网络检索数据并将数据保存到数据库以更新本地数据。

在下一章中，您将学习如何使用动画来改善应用程序的外观和设计。您将使用`CoordinatorLayout`和`MotionLayout`为您的应用程序添加动画和过渡效果。


# 第十五章：使用 CoordinatorLayout 和 MotionLayout 进行动画和过渡

概述

本章将向您介绍动画以及如何处理布局之间的变化。它涵盖了使用`MotionLayout`和 Android 中的 Motion Editor 描述移动对象的说明，以及对约束集进行详细解释。本章还涵盖了修改路径和为帧的运动添加关键帧。

通过本章结束时，您将能够使用`CoordinatorLayout`和`MotionLayout`创建动画，并使用 Android Studio 中的 Motion Editor 创建`MotionLayout`动画。

# 介绍

在上一章中，您了解了 MVVM 等架构模式。您现在知道如何改进应用程序的架构。接下来，我们将学习如何使用动画来增强我们应用程序的外观和感觉，并使其与其他应用程序不同且更好。

有时，我们开发的应用程序可能看起来有点单调。我们可以在应用程序中包含一些移动部分和令人愉悦的动画，使其更加生动，并使 UI 和用户体验更好。例如，我们可以添加视觉提示，以便用户不会困惑下一步该做什么，并可以引导他们可以采取哪些步骤。在加载时进行动画可以在内容被获取或处理时娱乐用户。当应用程序遇到错误时进行漂亮的动画可以帮助防止用户对发生的事情感到愤怒，并可以告知他们有哪些选项。

在本章中，我们将首先看一些在 Android 中进行动画的传统方法。我们将在本章结束时看一下较新的`MotionLayout`选项。让我们从活动过渡开始，这是最简单和最常用的动画之一。

# 活动过渡

在打开和关闭活动时，Android 会播放默认过渡。我们可以自定义活动过渡以反映品牌和/或区分我们的应用程序。活动过渡从 Android 5.0 Lollipop（API 级别 21）开始提供。

活动过渡有两部分：进入过渡和退出过渡。进入过渡定义了当活动打开时活动及其视图将如何进行动画。而退出过渡则描述了当活动关闭或打开新活动时活动和视图如何进行动画。Android 支持以下内置过渡：

+   **Explode**：这会将视图从中心移入或移出。

+   **Fade**：这会使视图缓慢出现或消失。

+   **Slide**：这会将视图从边缘移入或移出。

现在，让我们看看如何在下一节中添加活动过渡。有两种方法可以添加活动过渡：通过 XML 和通过代码。首先，我们将学习如何通过 XML 添加过渡，然后通过代码。

## 通过 XML 添加活动过渡

您可以通过 XML 添加活动过渡。第一步是启用窗口内容过渡。这是通过在`themes.xml`中添加活动的主题来完成的，如下所示：

```kt
<item name="android:windowActivityTransitions">true</item>
```

之后，您可以使用`android:windowEnterTransition`和`android:windowExitTransition`样式属性添加进入和退出过渡。例如，如果您想要使用来自`@android:transition/`的默认过渡，您需要添加的属性如下：

```kt
<item name="android:windowEnterTransition">  @android:transition/slide_left</item>
<item name="android:windowExitTransition">  @android:@transition/explode</item>
```

然后，您的`themes.xml`文件将如下所示：

```kt
    <style name="AppTheme"       parent="Theme.AppCompat.Light.DarkActionBar">
        ...
        <item name="android:windowActivityTransitions">true</item>
        <item name="android:windowEnterTransition">          @android:@transition/slide_left</item>
        <item name="android:windowExitTransition">          @android:@transition/explode</item>
    </style>
```

活动过渡通过`<item name="android:windowActivityTransitions">true</item>`启用。`<item name="android:windowEnterTransition">@android:transition/slide_left</item>`属性设置了进入过渡，而`@android:@transition/explode`是退出过渡文件，由`<item name="android:windowExitTransition">@android:transition/explode</item>`属性设置。

在下一节中，您将学习如何通过编码添加活动过渡。

## 通过代码添加活动过渡

活动转换也可以以编程方式添加。第一步是启用窗口内容转换。您可以在调用`setContentView()`之前在活动中调用以下函数来实现这一点：

```kt
window.requestFeature(Window.FEATURE_CONTENT_TRANSITIONS)
```

您可以随后使用`window.enterTransition`和`window.exitTransition`添加进入和退出事务。我们可以使用`android.transition`包中内置的`Explode()`，`Slide()`和`Fade()`转换。例如，如果我们想要使用`Explode()`作为进入转换和`Slide()`作为退出转换，我们可以添加以下代码：

```kt
window.enterTransition = Explode()
window.exitTransition = Slide()
```

如果您的应用程序的最低支持的 SDK 低于 21，请记得将这些调用包装在`Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP`的检查中。

现在您知道如何通过代码或 XML 添加进入和退出活动转换，您需要学习如何在打开活动时激活转换。我们将在下一节中进行。

## 使用 Activity 转换启动 Activity

一旦您向活动添加了活动转换（通过 XML 或编码），您可以在打开活动时激活转换。您应该传递一个带有转换动画的 bundle，而不是`startActivity(intent)`调用。为此，请使用以下代码启动您的活动：

```kt
startActivity(intent,ActivityOptions   .makeSceneTransitionAnimation(this).toBundle())
```

`ActivityOptions.makeSceneTransitionAnimation(this).toBundle()`参数将创建一个带有我们为活动指定的进入和退出转换的 bundle（通过 XML 或代码）。

通过向应用程序添加活动转换来尝试我们到目前为止所学到的内容。

## 练习 15.01：在应用程序中创建活动转换

在许多场所，留下小费（通常称为小费）是很常见的。这是为了表示对服务的感激而给出的一笔钱，例如给餐厅的服务员。小费是在最终账单上标明的基本费用之外提供的。

在本章中，我们将使用一个应用程序，该应用程序计算应该给出的小费金额。这个值将基于账单金额（基本费用）和用户想要给出的额外百分比。用户将输入这两个值，应用程序将计算小费金额。

在这个练习中，我们将自定义输入和输出屏幕之间的活动转换：

1.  在 Android Studio 中创建一个新项目。

1.  在`选择您的项目`对话框中，选择`空活动`，然后单击`下一步`。

1.  在`配置您的项目`对话框中，如*图 15.1*所示，将项目命名为`Tip Calculator`，并将包名称设置为`com.example.tipcalculator`：![图 15.1：配置您的项目对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_01.jpg)

图 15.1：配置您的项目对话框

1.  设置要保存项目的位置。选择`API 21：Android 5.0 Lollipop`作为`最低 SDK`，然后单击`完成`按钮。这将创建一个默认的`MainActivity`和一个布局文件`activity_main.xml`。

1.  将`MaterialComponents`依赖项添加到您的`app/build.gradle`文件中：

```kt
implementation 'com.google.android.material:material:1.2.1'
```

我们需要这样做才能使用`TextInputLayout`和`TextInputEditText`来输入文本字段。

1.  打开`themes.xml`文件，并确保活动的主题使用`MaterialComponents`的主题。参见以下示例：

```kt
<style name="AppTheme"   parent="Theme.MaterialComponents.Light.DarkActionBar">
```

我们需要这样做，因为我们稍后将使用的`TextInputLayout`和`TextInputEditText`需要您的活动使用`MaterialComponents`主题。

1.  打开`activity_main.xml`。删除`Hello World` `TextView`并添加金额的输入文本字段：

```kt
<com.google.android.material.textfield.TextInputLayout
    android:id="@+id/amount_text_layout"
    style="@style/Widget.MaterialComponents       .TextInputLayout.OutlinedBox"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:layout_marginStart="16dp"
    android:layout_marginTop="100dp"
    android:layout_marginEnd="16dp"
    android:layout_marginBottom="16dp"
    android:alpha="1"
    android:hint="Amount"
    app:layout_constraintEnd_toEndOf="parent"
    app:layout_constraintStart_toStartOf="parent"
    app:layout_constraintTop_toTopOf="parent">
    <com.google.android.material.textfield       .TextInputEditText
        android:id="@+id/amount_text"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:inputType="numberDecimal"
        android:textSize="18sp" />
</com.google.android.material.textfield.TextInputLayout>
```

1.  在金额文本字段下方添加另一个小费百分比的输入文本字段：

```kt
<com.google.android.material.textfield.TextInputLayout
    android:id="@+id/percent_text_layout"
    style="@style/Widget.MaterialComponents       .TextInputLayout.OutlinedBox"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:layout_margin="16dp"
    android:alpha="1"
    android:hint="Tip Percent"
    app:layout_constraintEnd_toEndOf="parent"
    app:layout_constraintStart_toStartOf="parent"
    app:layout_constraintTop_toBottomOf       ="@id/amount_text_layout">
    <com.google.android.material.textfield       .TextInputEditText
        android:id="@+id/percent_text"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:inputType="numberDecimal"
        android:textSize="18sp" />
</com.google.android.material.textfield.TextInputLayout>
```

1.  最后，在小费百分比文本字段底部添加一个`计算`按钮：

```kt
<Button
    android:id="@+id/compute_button"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:layout_marginTop="36dp"
    android:text="Compute"
    app:layout_constraintEnd_toEndOf       ="@+id/percent_text_layout"
    app:layout_constraintTop_toBottomOf       ="@+id/percent_text_layout" />
```

1.  创建另一个活动。转到`文件`菜单，单击`新建` | `活动` | `空活动`。将其命名为`OutputActivity`。确保选中`生成布局文件`，以便创建`activity_output`。

1.  打开`MainActivity`。在`onCreate`函数的末尾，添加以下代码：

```kt
        val amountText: EditText =           findViewById(R.id.amount_text)
        val percentText: EditText =           findViewById(R.id.percent_text)
        val computeButton: Button =           findViewById(R.id.compute_button)
        computeButon.setOnClickListener {
            val amount =
                if (amountText.text.toString().isNotBlank())                   amountText.text.toString() else "0"
            val percent =
                if (percentText.text.toString().isNotBlank())                   percentText.text.toString() else "0"
            val intent = Intent(this,               OutputActivity::class.java).apply {
                putExtra("amount", amount)
                putExtra("percent", percent)
            }
            startActivity(intent)
        }
```

这将为`Compute`按钮添加一个`ClickListener`组件，这样当点击时，系统将打开`OutputActivity`并将金额和百分比值作为意图额外传递。

1.  打开`activity_output.xml`并添加一个用于显示小费的`TextView`：

```kt
   <TextView
        android:id="@+id/tip_text"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        style="@style/TextAppearance.AppCompat.Headline"
        tools:text="The tip is " />
```

1.  打开`OutputActivity`。在`onCreate`函数的末尾，添加以下代码：

```kt
        val amount = intent?.getStringExtra("amount")          ?.toBigDecimal() ?: BigDecimal.ZERO
        val percent = intent?.getStringExtra("percent")          ?.toBigDecimal() ?: BigDecimal.ZERO
        val tip = amount * (percent.divide("100"          .toBigDecimal()))
        val tipText: TextView = findViewById(R.id.tip_text)
        tipText.text = "The tip is $tip"
```

这将根据输入金额和百分比计算并显示小费。

1.  运行应用程序。点击`Compute`按钮，注意打开`OutputActivity`和返回时发生的情况。在关闭`MainActivity`和打开/关闭`OutputActivity`时，会有默认动画。

1.  现在，让我们开始添加过渡动画。打开`themes.xml`并使用`windowActivityTransitions`，`windowEnterTransition`和`windowExitTransition`样式属性更新活动主题：

```kt
        <item name="android:windowActivityTransitions">          true</item>
        <item name="android:windowEnterTransition">          @android:transition/explode</item>
        <item name="android:windowExitTransition">          @android:transition/slide_left</item>
```

这将启用活动过渡，添加一个爆炸进入过渡，并向活动添加一个向左滑动退出过渡。

1.  返回`MainActivity`文件，并用以下内容替换`startActivity(intent)`：

```kt
startActivity(intent, ActivityOptions   .makeSceneTransitionAnimation(this).toBundle())
```

这将使用我们在上一步中设置的 XML 文件中指定的过渡动画打开`OutputActivity`。

1.  运行应用程序。您会看到打开和关闭`MainActivity`和`OutputActivity`时的动画已经改变。当 Android UI 打开`OutputActivity`时，您会注意到文本向中心移动。在关闭时，视图向左滑动：

![图 15.2：应用程序屏幕：输入屏幕（左侧）和输出屏幕（右侧）](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_02.jpg)

图 15.2：应用程序屏幕：输入屏幕（左侧）和输出屏幕（右侧）

我们已经为应用程序添加了活动过渡。当我们打开一个新的活动时，新活动的进入过渡将播放。当活动被关闭时，将播放其退出过渡。

有时，当我们从一个活动打开另一个活动时，两个活动中存在一个共同的元素。在下一节中，我们将学习如何添加这个共享元素过渡。

## 添加共享元素过渡

有时，一个应用程序从一个活动转移到另一个活动，两个活动中都存在一个共同的元素。我们可以为这个共享元素添加动画，以突出向用户展示两个活动之间的链接。

例如，在一个电影应用程序中，一个包含电影列表（带有缩略图图像）的活动可以打开一个新的活动，显示所选电影的详细信息，并在顶部显示全尺寸图像。为图像添加共享元素过渡将把列表活动上的缩略图与详细信息活动上的图像链接起来。

共享元素过渡有两部分：进入过渡和退出过渡。这些过渡可以通过 XML 或代码完成。

第一步是启用窗口内容过渡。您可以通过将活动的主题添加到`themes.xml`中来实现：

```kt
<item name="android:windowContentTransitions">true</item>
```

您还可以通过在调用`setContentView()`之前在活动中调用以下函数来以编程方式执行此操作：

```kt
window.requestFeature(Window.FEATURE_CONTENT_TRANSITIONS)
```

`android:windowContentTransitions`属性的值为`true`，`window.requestFeature(Window.FEATURE_CONTENT_TRANSITIONS)`将启用窗口内容过渡。

之后，您可以添加共享元素进入过渡和共享元素退出过渡。如果您的`res/transitions`目录中有`enter_transition.xml`和`exit_transition.xml`，您可以通过添加以下样式属性来添加共享元素进入过渡：

```kt
<item name="android:windowSharedElementEnterTransition">  @transition/enter_transition</item>
```

您也可以通过以下代码以编程方式完成这一操作：

```kt
val enterTransition = TransitionInflater.from(this)  .inflateTransition(R.transition.enter_transition)
window.sharedElementEnterTransition = enterTransition
```

`windowSharedElementEnterTransition`属性和`window.sharedElementEnterTransition`将把我们的进入过渡设置为`enter_transition.xml`文件。

要添加共享元素退出过渡，可以添加以下样式属性：

```kt
<item name="android:windowSharedElementExitTransition">  @transition/exit_transition</item>
```

这可以通过以下代码以编程方式完成：

```kt
val exitTransition = TransitionInflater.from(this)  .inflateTransition(R.transition.exit_transition)
window.sharedElementExitTransition = exitTransition
```

`windowSharedElementExitTransition`属性和`window.sharedElementExitTransition`将把我们的退出过渡设置为`exit_transition.xml`文件。

您已经学会了如何添加共享元素过渡。在下一节中，我们将学习如何开始具有共享元素过渡的活动。

## 使用共享元素过渡开始活动

一旦您向活动添加了共享元素过渡（无论是通过 XML 还是通过编程方式），您可以在打开活动时激活过渡。在这之前，添加一个`transitionName`属性。将其值设置为两个活动中共享元素的相同文本。

例如，在`ImageView`中，我们可以为`transitionName`属性添加一个`transition_name`值：

```kt
    <ImageView
        ...
        android:transitionName="transition_name"
        android:id="@+id/sharedImage"
    ... />
```

要开始具有共享元素的活动，我们将传递一个带有过渡动画的 bundle。为此，请使用以下代码启动您的活动：

```kt
startActivity(intent, ActivityOptions   .makeSceneTransitionAnimation(this, sharedImage,     "transition_name").toBundle());
```

`ActivityOptions.makeSceneTransitionAnimation(this, sharedImage, "transition_name").toBundle()`参数将创建一个带有共享元素（`sharedImage`）和过渡名称（`transition_name`）的 bundle。

如果有多个共享元素，您可以传递`Pair<View, String>`的可变参数，其中`View`和过渡名称`String`。例如，如果我们将视图的按钮和图像作为共享元素，我们可以这样做：

```kt
val buttonPair: Pair<View, String> = Pair(button, "button") 
val imagePair: Pair<View, String> = Pair(image, "image") 
val activityOptions = ActivityOptions   .makeSceneTransitionAnimation(this, buttonPair, imagePair)
startActivity(intent, activityOptions.toBundle())
```

注意

请记住导入`android.util.Pair`而不是`kotlin.Pair`，因为`makeSceneTransitionAnimation`需要来自 Android SDK 的 pair。

让我们尝试一下到目前为止学到的内容，通过向*Tip Calculator*应用程序添加共享元素过渡。

## 练习 15.02：创建共享元素过渡

在第一个练习中，我们为`MainActivity`和`OutputActivity`自定义了活动过渡。在这个练习中，我们将向两个活动添加一个图像。当从输入屏幕移动到输出屏幕时，将对此共享元素进行动画处理。我们将使用应用程序启动器图标（`res/mipmap/ic_launcher`）作为`ImageView`。您可以更改您的图标，而不是使用默认的：

1.  打开我们在`Exercise 15.01`中开发的`Tip Calculator`项目，创建活动过渡。

1.  转到`activity_main.xml`文件，并在金额文本字段顶部添加一个`ImageView`：

```kt
    <ImageView
        android:id="@+id/image"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginTop="100dp"
        android:src="img/ic_launcher"
        android:transitionName="transition_name"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent" />
```

`transitionName`值为`transition_name`将用于标识此为共享元素。

1.  通过更改`app:layout_constraintTop_toTopOf="parent"`来更改`amount_text_layout` `TextInputLayout`的顶部约束为以下内容：

```kt
app:layout_constraintTop_toBottomOf="@id/image"
```

这将使金额`TextInputLayout`类移动到图像下方。

1.  现在，打开`activity_output.xml`文件，并在`tip TextView`上方添加一个图像，高度和宽度为 200dp，`scaleType`为`fitXY`以适应图像到`ImageView`的尺寸。

```kt
    <ImageView
        android:id="@+id/image"
        android:layout_width="200dp"
        android:layout_height="200dp"
        android:layout_marginBottom="40dp"
        android:src="img/ic_launcher"
        android:scaleType="fitXY"
        android:transitionName="transition_name"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintBottom_toTopOf="@id/tip_text" />
```

`transitionName`值为`transition_name`与`MainActivity`中的`ImageView`的值相同。

1.  打开`MainActivity`并将`startActivity`代码更改为以下内容：

```kt
val image: ImageView = findViewById(R.id.image)
startActivity(intent, ActivityOptions   .makeSceneTransitionAnimation(this, image,     "transition_name").toBundle())
```

这将从`MainActivity`中的 ID 为 image 的`ImageView`开始一个过渡，到`OutputActivity`中另一个具有`transitionName`值也为`transition_name`的图像。

1.  运行应用程序。提供金额和百分比，然后点击`Compute`按钮。您会看到输入活动中的图像似乎放大并定位到`OutputActivity`中：

![图 15.3：应用程序屏幕：输入屏幕（左侧）和输出屏幕（右侧）](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_03.jpg)

图 15.3：应用程序屏幕：输入屏幕（左侧）和输出屏幕（右侧）

我们已经学会了如何添加活动过渡和共享元素过渡。现在，让我们来看看如何在布局中对视图进行动画处理。如果内部有多个元素，要对每个元素进行动画处理可能会很困难。`CoordinatorLayout`可用于简化此动画。我们将在下一节中讨论这个问题。

# 使用 CoordinatorLayout 进行动画

`CoordinatorLayout`是一个处理其子视图之间动作的布局。当您将`CoordinatorLayout`用作父视图组时，可以轻松地对其中的视图进行动画处理。您可以通过在`app/build.gradle`文件的依赖项中添加以下内容将`CoordinatorLayout`添加到您的项目中：

```kt
implementation 'androidx.coordinatorlayout:coordinatorlayout:1.1.0'
```

这将允许我们在布局文件中使用`CoordinatorLayout`。

假设我们有一个布局文件，其中包含`CoordinatorLayout`内的浮动操作按钮。当点击浮动操作按钮时，UI 会显示一个`Snackbar`消息。

注意

`Snackbar`是一个 Android 小部件，可以在屏幕底部向用户提供简短的消息。

如果您使用的是除`CoordinatorLayout`之外的任何布局，则带有消息的 Snackbar 将呈现在浮动操作按钮的顶部。如果我们将`CoordinatorLayout`用作父视图组，布局将向上推动浮动操作按钮，将 Snackbar 显示在其下方，并在 Snackbar 消失时将其移回。*图 15.4*显示了布局如何调整以防止 Snackbar 位于浮动操作按钮的顶部：

![图 15.4：左侧截图显示了 Snackbar 显示之前和之后的 UI。右侧的截图显示了 Snackbar 可见时的 UI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_04.jpg)

图 15.4：左侧截图显示了 Snackbar 显示之前和之后的 UI。右侧的截图显示了 Snackbar 可见时的 UI

浮动操作按钮移动并为 Snackbar 消息提供空间，因为它具有名为`FloatingActionButton.Behavior`的默认行为，这是`CoordinatorLayout.Behavior`的子类。`FloatingActionButton.Behavior`在显示 Snackbar 时移动浮动操作按钮，以便 Snackbar 不会覆盖浮动操作按钮。

并非所有视图都具有`CoordinatorLayout`行为。要实现自定义行为，可以通过扩展`CoordinatorLayout.Behavior`来开始。然后，您可以使用`layout_behavior`属性将其附加到视图上。例如，如果我们在`com.example.behavior`包中为按钮创建了`CustomBehavior`，我们可以在布局中使用以下内容更新按钮：

```kt
...
<Button
    ...
    app:layout_behavior="com.example.behavior.CustomBehavior">
    .../>
```

我们已经学会了如何使用`CoordinatorLayout`创建动画和过渡。在下一节中，我们将研究另一个布局`MotionLayout`，它允许开发人员更多地控制动作。

# 使用 MotionLayout 创建动画

在 Android 中创建动画有时是耗时的。即使是创建简单的动画，您也需要处理 XML 和代码文件。更复杂的动画和过渡需要更多的时间来制作。

为了帮助开发人员轻松制作动画，Google 创建了`MotionLayout`。`MotionLayout`是通过 XML 创建动作和动画的新方法。它从 API 级别 14（Android 4.0）开始提供。

使用`MotionLayout`，我们可以对一个或多个视图的位置、宽度/高度、可见性、透明度、颜色、旋转、高程和其他属性进行动画处理。通常，其中一些属性很难通过代码实现，但`MotionLayout`允许我们使用声明性 XML 轻松调整它们，以便我们可以更多地专注于我们的应用程序。

让我们开始通过将`MotionLayout`添加到我们的应用程序中。

## 添加 MotionLayout

要将`MotionLayout`添加到您的项目中，您只需要添加 ConstraintLayout 2.0 的依赖项。ConstraintLayout 2.0 是 ConstraintLayout 的新版本，增加了包括`MotionLayout`在内的新功能。在您的 app/`build.gradle`文件的依赖项中添加以下内容：

```kt
implementation 'androidx.constraintlayout:constraintlayout:2.0.4'
```

这将向您的应用程序添加最新版本的 ConstraintLayout（在撰写本文时为 2.0.4）。对于本书，我们将使用 AndroidX 版本。如果您尚未更新项目，请考虑从支持库更新到 AndroidX。

添加依赖项后，我们现在可以使用`MotionLayout`来创建动画。我们将在下一节中进行这样的操作。

## 使用 MotionLayout 创建动画

`MotionLayout`是我们好朋友 ConstraintLayout 的一个子类。要使用`MotionLayout`创建动画，请打开要添加动画的布局文件。将根 ConstraintLayout 容器替换为`androidx.constraintlayout.motion.widget.MotionLayout`。

动画本身不会在布局文件中，而是在另一个名为`motion_scene`的 XML 文件中。`motion_scene`将指定`MotionLayout`如何对其中的视图进行动画。`motion_scene`文件应放置在`res/xml`目录中。布局文件将使用根视图组中的`app:layoutDescription`属性链接到这个`motion_scene`文件。您的布局文件应该类似于以下内容：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.motion.widget.MotionLayout
    ...
    app:layoutDescription="@xml/motion_scene">
    ...
</androidx.constraintlayout.motion.widget.MotionLayout>
```

要使用`MotionLayout`创建动画，我们必须有视图的初始状态和最终状态。`MotionLayout`将自动在两者之间进行过渡动画。您可以在同一个`motion_scene`文件中指定这两个状态。如果布局中有很多视图，您还可以使用两个不同的布局来表示动画的开始和结束状态。

`motion_scene`文件的根容器是`motion_scene`。这是我们为`MotionLayout`添加约束和动画的地方。它包含以下内容：

+   **ConstraintSet**：指定要进行动画的视图/布局的开始和结束位置和样式。

+   **Transition**：指定要在视图上执行的动画的开始、结束、持续时间和其他详细信息。

让我们尝试通过将其添加到我们的*Tip Calculator*应用程序中，使用`MotionLayout`添加动画。

## 练习 15.03：使用 MotionLayout 添加动画

在这个练习中，我们将使用`MotionLayout`动画更新我们的*Tip Calculator*应用程序。在输出屏幕上，点击图像将向下移动，并在再次点击时返回到原始位置：

1.  在 Android Studio 4.0 或更高版本中打开*Tip Calculator*项目。

1.  打开`app/build.gradle`文件，并用以下内容替换`ConstraintLayout`的依赖项：

```kt
implementation 'androidx   .constraintlayout:constraintlayout:2.0.4'
```

有了这个，我们就可以在我们的布局文件中使用`MotionLayout`了。

1.  打开`activity_output.xml`文件，并将根`ConstraintLayout`标记更改为`MotionLayout`。将`androidx.constraintlayout.widget.ConstraintLayout`更改为以下内容：

```kt
androidx.constraintlayout.motion.widget.MotionLayout
```

1.  将`app:layoutDescription="@xml/motion_scene"`添加到`MotionLayout`标记中。IDE 将警告您该文件尚不存在。暂时忽略，因为我们将在下一步中添加它。您的文件应该类似于这样：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.motion.widget.MotionLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    app:layoutDescription="@xml/motion_scene"
    tools:context=".OutputActivity">
    ...
</androidx.constraintlayout.motion.widget.MotionLayout>
```

1.  在`res/xml`目录中创建一个`motion_scene.xml`文件。这将是我们的`motion_scene`文件，其中将定义动画配置。使用`motion_scene`作为文件的根元素。

1.  通过在`motion_scene`文件中添加以下内容来添加起始的`Constraint`元素：

```kt
   <ConstraintSet android:id="@+id/start_constraint">
        <Constraint
            android:id="@id/image"
            android:layout_width="200dp"
            android:layout_height="200dp"
            android:layout_marginBottom="40dp"
            app:layout_constraintBottom_toTopOf="@id/tip_text"
            app:layout_constraintEnd_toEndOf="parent"
            app:layout_constraintStart_toStartOf="parent" />
    </ConstraintSet>
```

这是图像在当前位置的样子（约束在屏幕顶部）。

1.  接下来，在`motion_scene`文件中添加结束的`Constraint`元素，方法如下：

```kt
    <ConstraintSet android:id="@+id/end_constraint">
        <Constraint
            android:id="@id/image"
            android:layout_width="200dp"
            android:layout_height="200dp"
            android:layout_marginBottom="40dp"
            app:layout_constraintBottom_toBottomOf="parent"
            app:layout_constraintEnd_toEndOf="parent"
            app:layout_constraintStart_toStartOf="parent" />
    </ConstraintSet>
```

在结束动画时，`ImageView`将位于屏幕底部。

1.  现在让我们为`ImageView`添加过渡效果：

```kt
    <Transition
        app:constraintSetEnd="@id/end_constraint"
        app:constraintSetStart="@id/start_constraint"
        app:duration="2000">
        <OnClick
            app:clickAction="toggle"
            app:targetId="@id/image" />
    </Transition>
```

在这里，我们正在指定开始和结束的约束条件，将在 2,000 毫秒（2 秒）内进行动画。我们还在`ImageView`上添加了一个`OnClick`事件。切换将使视图从开始到结束进行动画，如果视图已经处于结束状态，它将动画返回到开始状态。

1.  您完成的`motion_scene.xml`文件应如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<MotionScene xmlns:android   ="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto">
    <ConstraintSet android:id="@+id/start_constraint">
        <Constraint
            android:id="@id/image"
            android:layout_width="200dp"
            android:layout_height="200dp"
            android:layout_marginBottom="40dp"
            app:layout_constraintBottom_toTopOf="@id/tip_text"
            app:layout_constraintEnd_toEndOf="parent"
            app:layout_constraintStart_toStartOf="parent" />
    </ConstraintSet>
    <ConstraintSet android:id="@+id/end_constraint">
        <Constraint
            android:id="@id/image"
            android:layout_width="200dp"
            android:layout_height="200dp"
            android:layout_marginBottom="40dp"
            app:layout_constraintBottom_toBottomOf="parent"
            app:layout_constraintEnd_toEndOf="parent"
            app:layout_constraintStart_toStartOf="parent" />
    </ConstraintSet>
    <Transition
        app:constraintSetEnd="@id/end_constraint"
        app:constraintSetStart="@id/start_constraint"
        app:duration="2000">
        <OnClick
            app:clickAction="toggle"
            app:targetId="@id/image" />
    </Transition>
</MotionScene>
```

1.  运行应用程序并点击`ImageView`。它将在大约 2 秒内直线向下移动。再次点击它，它将在 2 秒内向上移动。*图 15.5*显示了此动画的开始和结束：

![图 15.5：起始动画（左）和结束动画（右）](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_05.jpg)

图 15.5：起始动画（左）和结束动画（右）

在这个练习中，我们通过指定开始约束、结束约束和持续时间以及`OnClick`事件，在`MotionLayout`中对`ImageView`进行了动画处理。`MotionLayout`会自动播放动画，从开始位置到结束位置（对我们来说，看起来就像在轻按时自动上下移动）。

我们已经使用`MotionLayout`创建了动画。在下一节中，我们将使用 Android Studio 的 Motion Editor 来创建`MotionLayout`动画。

## Motion Editor

从 4.0 版本开始，Android Studio 包括了 Motion Editor。Motion Editor 可以帮助开发人员使用`MotionLayout`创建动画。这使得开发人员更容易创建和预览过渡和其他动作，而不是手工操作并运行来查看更改。编辑器还会自动生成相应的文件。

您可以通过右键单击预览并单击`Convert to MotionLayout`来将 ConstraintLayout 转换为 MotionLayout。Android Studio 会进行转换，还会为您创建动作场景文件。

在`Design`视图中查看具有`MotionLayout`作为根的布局文件时，Motion Editor UI 将包含在`Design`视图中，如*图 15.6*所示：

![图 15.6：Android Studio 4.0 中的 Motion Editor](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_06.jpg)

图 15.6：Android Studio 4.0 中的 Motion Editor

在右上窗口（`Overview`面板）中，您可以看到`MotionLayout`的可视化以及开始和结束约束。过渡显示为从开始的箭头。靠近开始约束的点显示了过渡的点击操作。*图 15.7*显示了选择了`start_constraint`的`Overview`面板：

![图 15.7：Motion Editor 的概述面板中选择了 start_constraint](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_07.jpg)

图 15.7：选择了 start_constraint 的 Motion Editor 的概述面板

右下窗口是`Selection`面板，显示了在`Overview`面板中选择的约束集或`MotionLayout`中的视图。当选择过渡箭头时，它还可以显示过渡。*图 15.8*显示了选择`start_constraint`时的`Selection`面板：

![图 15.8：Motion Editor 的选择面板显示了 start_constraint 的 ConstraintSet](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_08.jpg)

图 15.8：Motion Editor 的选择面板显示了 start_constraint 的 ConstraintSet

当您在`Overview`面板的左侧点击`MotionLayout`时，下方的`Selection`面板将显示视图及其约束，如*图 15.9*所示：

![图 15.9：选择 MotionLayout 时的概述和选择面板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_09.jpg)

图 15.9：选择 MotionLayout 时的概述和选择面板

当您点击`start_constraint`或`end_constraint`时，左侧的预览窗口将显示开始或结束状态的外观。`Selection`面板还会显示视图及其约束。看一下*图 15.10*，看看选择`start_constraint`时的外观：

![图 15.10：选择了 start_constraint 时 Motion Editor 的外观](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_10.jpg)

图 15.10：选择了 start_constraint 时 Motion Editor 的外观

*图 15.11*显示了如果选择`end_constraint`，Motion Editor 会是什么样子：

![图 15.11：选择 end_constraint 时 Motion Editor 的外观](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_11.jpg)

图 15.11：选择 end_constraint 时 Motion Editor 的外观

连接`start_constraint`和`end_constraint`的箭头代表了`MotionLayout`的过渡。在`Selection`面板上，有播放或转到第一个/最后一个状态的控件。您还可以将箭头拖动到特定位置。*图 15.12*显示了动画中间的外观（50%）：

![图 15.12：动画中间的过渡](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_12.jpg)

图 15.12：动画中间的过渡

在开发带有`MotionLayout`的动画时，最好能够调试动画以确保我们做得正确。我们将在下一节讨论如何做到这一点。

## 调试 MotionLayout

为了帮助您在运行应用程序之前可视化`MotionLayout`动画，您可以在 Motion Editor 中显示运动路径和动画的进度。运动路径是要动画的对象从起始状态到结束状态所采取的直线路线。

显示路径和/或进度动画，我们可以向`MotionLayout`容器添加`motionDebug`属性。我们可以使用以下值来设置`motionDebug`：

+   `SHOW_PATH`：仅显示运动路径。

+   `SHOW_PROGRESS`：仅显示动画进度。

+   `SHOW_ALL`：显示动画的路径和进度。

+   `NO_DEBUG`：隐藏所有动画。

要显示`MotionLayout`路径和进度，我们可以使用以下内容：

```kt
<androidx.constraintlayout.motion.widget.MotionLayout
    ...
    app:motionDebug="SHOW_ALL"
    ...>
```

`SHOW_ALL`值将显示动画的路径和进度。*图 15.13*显示了当我们使用`SHOW_PATH`和`SHOW_PROGRESS`时的效果：

![图 15.13：使用 SHOW_PATH（左）显示动画路径，而 SHOW_PROGRESS（右）显示动画进度](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_13.jpg)

图 15.13：使用 SHOW_PATH（左）显示动画路径，而 SHOW_PROGRESS（右）显示动画进度

虽然`motionDebug`听起来像是只在调试模式下出现的东西，但它也会出现在发布版本中，因此在准备应用程序发布时应将其删除。

在`MotionLayout`动画期间，起始约束将过渡到结束约束，即使有一个或多个元素可以阻挡运动中的对象。我们将在下一节讨论如何避免这种情况发生。

## 修改 MotionLayout 路径

在`MotionLayout`动画中，UI 将从起始约束播放动作到结束约束，即使中间有元素可以阻挡我们移动的视图。例如，如果`MotionLayout`涉及从屏幕顶部到底部移动的文本，然后反之，我们在中间添加一个按钮，按钮将覆盖移动的文本。

*图 15.14*显示了`OK`按钮如何挡住了动画中间的移动文本：

![图 15.14：OK 按钮挡住了文本动画的中间部分](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_14.jpg)

图 15.14：OK 按钮挡住了文本动画的中间部分

`MotionLayout`以直线路径播放动画从起始到结束约束，并根据指定的属性调整视图。我们可以在起始和结束约束之间添加关键帧来调整动画路径和/或视图属性。例如，在动画期间，除了改变移动文本的位置以避开按钮之外，我们还可以改变文本或其他视图的属性。

关键帧可以作为`motion_scene`的过渡属性的子级添加到`KeyFrameSet`中。我们可以使用以下关键帧：

+   `KeyPosition`：指定动画过程中特定点上视图的位置以调整路径。

+   `KeyAttribute`：指定动画过程中特定点上视图的属性。

+   `KeyCycle`：在动画期间添加振荡。

+   `KeyTimeCycle`：这允许循环由时间驱动而不是动画进度。

+   `KeyTrigger`：添加一个可以根据动画进度触发事件的元素。

我们将重点放在`KeyPosition`和`KeyAttribute`上，因为`KeyCycle`、`KeyTimeCycle`和`KeyTrigger`是更高级的关键帧，并且仍然可能会发生变化。

`KeyPosition`允许我们在`MotionLayout`动画中更改视图的位置。它具有以下属性：

+   `motionTarget`：指定由关键帧控制的对象。

+   `framePosition`：从 1 到 99 编号，指定位置将在动作变化时的百分比。例如，25 表示动画的四分之一处，50 表示动画的中间点。

+   `percentX`：指定路径的`x`值将被修改多少。

+   `percentY`：指定路径的`y`值将被修改多少。

+   `keyPositionType`：指定`KeyPosition`如何修改路径。

`keyPositionType`属性可以具有以下值：

+   `parentRelative`：`percentX`和`percentY`是基于视图的父级指定的。

+   `pathRelative`：`percentX`和`percentY`是基于从开始约束到结束约束的直线路径指定的。

+   `deltaRelative`：`percentX`和`percentY`是基于视图位置指定的。

例如，如果我们想要在动画的正中间（50%）修改`text_view` ID 的`TextView`的路径，通过将其相对于`TextView`的父容器在`x`和`y`方向上移动 10%，我们将在`motion_scene`中有以下关键位置：

```kt
<KeyPosition
    app:motionTarget="@+id/text_view"
    app:framePosition="50"
    app:keyPositionType="parentRelative"
    app:percentY="0.1"
    app:percentX="0.1"
/>
```

同时，`KeyAttribute`允许我们在`MotionLayout`动画进行时更改视图的属性。我们可以更改的一些视图属性包括`visibility`、`alpha`、`elevation`、`rotation`、`scale`和`translation`。它具有以下属性：

+   `motionTarget`：指定由关键帧控制的对象。

+   `framePosition`：从 1 到 99 编号，指定应用视图属性的动作百分比。例如，20 表示动画的五分之一处，75 表示动画的四分之三处。

让我们尝试向*Tip Calculator*应用程序添加关键帧。在`ImageView`的动画过程中，它会覆盖显示小费的文本。我们将使用关键帧来解决这个问题。

## 练习 15.04：使用关键帧修改动画路径

在上一个练习中，我们动画化了图像在被点击时向下移动（或者当它已经在底部时向上移动）。当图像处于中间位置时，它会覆盖小费`TextView`。我们将通过在 Android Studio 的 Motion Editor 中向`motion_scene`添加`KeyFrame`来解决这个问题：

1.  使用 Android Studio 4.0 或更高版本打开*Tip Calculator*应用程序。

1.  在`res/layout`目录中打开`activity_output.xml`文件。

1.  切换到`Design`视图。

1.  将`app:motionDebug="SHOW_ALL"`添加到`MotionLayout`容器中。这将允许我们在 Android Studio 和设备/模拟器上看到路径和进度信息。您的`MotionLayout`容器将如下所示：

```kt
<androidx.constraintlayout.motion.widget.MotionLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    app:layoutDescription="@xml/motion_scene"
    app:motionDebug="SHOW_ALL"
        tools:context=".OutputActivity"> 
```

1.  运行应用程序并进行计算。在输出屏幕上，点击图像。观察动画进行时的小费文本。您会注意到在动画的中间，图像会覆盖文本，如*图 15.15*所示：![图 15.15：图像遮挡显示小费的 TextView](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_15.jpg)

图 15.15：图像遮挡显示小费的 TextView

1.  返回 Android Studio 中的`activity_output.xml`文件。确保它在`Design`视图中打开。

1.  在右上角的`Overview`面板中，单击连接`start_constraint`和`end_constraint`的箭头。在`Selection`面板中将下箭头拖到中间（50%），如*图 15.16*所示：![图 15.16：选择表示过渡的箭头开始和结束约束](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_16.jpg)

图 15.16：选择表示开始和结束约束之间过渡的箭头

1.  点击`Selection`面板中`Transition`右侧的`Create KeyFrames`图标（带有绿色`+`符号）。参考*图 15.17*查看图标：![图 15.17：创建关键帧图标](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_17.jpg)

图 15.17：创建关键帧图标

1.  选择`KeyPosition`。我们将使用`KeyPosition`来调整文本位置，避免按钮。

1.  选择`ID`，选择`image`，并将输入位置设置为`50`。`Type`为`parentRelative`，`PercentX`为`1.5`，如*图 15.18*所示。这将在过渡的中间（50%）为图像添加一个`KeyPosition`属性，相对于父视图的`x`轴为 1.5 倍：![图 15.18：提供要进行的关键位置的输入](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_18.jpg)

图 15.18：提供要进行的关键位置的输入

1.  点击`Add`按钮。你会在`Design`预览中看到，如*图 15.19*所示，运动路径不再是一条直线。在位置 50（动画的中间），文本将不再被`ImageView`覆盖。`ImageView`将位于`TextView`的右侧：![图 15.19：路径现在将是曲线而不是直线。过渡面板还将添加一个新的`KeyPosition`项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_19.jpg)

图 15.19：路径现在将是曲线而不是直线。过渡面板还将添加一个新的`KeyPosition`项目

1.  点击播放图标查看动画效果。在设备或模拟器上运行应用程序进行验证。你会看到动画现在向右弯曲，而不是沿着以前的直线路径，如*图 15.20*所示：![图 15.20：动画现在避开了带有提示的 TextView](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_20.jpg)

图 15.20：动画现在避开了带有提示的 TextView

1.  Motion Editor 将自动生成`KeyPosition`的代码。如果你转到`motion_scene.xml`文件，你会看到 Motion Editor 在过渡属性中添加了以下代码：

```kt
<KeyFrameSet>
    <KeyPosition
        app:framePosition="50"
        app:keyPositionType="parentRelative"
        app:motionTarget="@+id/image"
        app:percentX="1.5" />
</KeyFrameSet>
```

在过渡期间的关键帧中添加了`KeyPosition`属性。在动画的 50%处，图像的`x`位置将相对于其父视图移动 1.5 倍。这允许图像在动画过程中避开其他元素。

在这个练习中，你已经添加了一个关键位置，它将调整`MotionLayout`动画，使其不会阻塞或被路径中的其他视图阻塞。

让我们通过做一个活动来测试你学到的一切。

## 活动 15.01：密码生成器

使用强密码来保护我们的在线账户是很重要的。它必须是独一无二的，必须包括大写和小写字母，数字和特殊字符。在这个活动中，你将开发一个可以生成强密码的应用程序。

该应用程序将有两个屏幕：输入屏幕和输出屏幕。在输入屏幕上，用户可以提供密码的长度，并指定它是否必须包含大写或小写字母，数字或特殊字符。输出屏幕将显示三个可能的密码，当用户选择一个时，其他密码将移开，并显示一个按钮将密码复制到剪贴板。你应该自定义从输入到输出屏幕的转换。

完成的步骤如下：

1.  在 Android Studio 4.0 或更高版本中创建一个名为`Password Generator`的新项目。设置它的包名和`Minimum SDK`。

1.  将`MaterialComponents`依赖项添加到你的`app/build.gradle`文件中。

1.  更新`ConstraintLayout`的依赖关系。

1.  确保活动的主题在`themes.xml`文件中使用了`MaterialComponents`的主题。

1.  在`activity_main.xml`文件中，删除`Hello World`的`TextView`，并添加密码长度的输入文本字段。

1.  为大写字母、数字和特殊字符添加复选框代码。

1.  在复选框底部添加一个`Generate`按钮。

1.  创建另一个名为`OutputActivity`的活动。

1.  自定义从输入屏幕（`MainActivity`）到`OutputActivity`的活动转换。打开`themes.xml`并使用`windowActivityTransitions`，`windowEnterTransition`和`windowExitTransition`样式属性更新活动主题。

1.  更新`MainActivity`中`onCreate`函数的结尾。

1.  更新`activity_output.xml`文件中`androidx.constraintlayout.widget.ConstraintLayout`的代码。

1.  在`MotionLayout`标签中添加`app:layoutDescription="@xml/motion_scene"`和`app:motionDebug="SHOW_ALL"`。

1.  在输出活动中为生成的三个密码添加三个`TextView`实例。

1.  在屏幕底部添加一个“复制”按钮。

1.  在`OutputActivity`中添加`generatePassword`函数。

1.  添加代码根据用户输入生成三个密码，并为用户添加一个`ClickListener`组件，以便将所选密码复制到剪贴板。

1.  在`OutputActivity`中，为每个密码`TextView`创建一个动画。

1.  为默认视图创建`ConstraintSet`。

1.  当选择第一个、第二个和第三个密码时，添加`ConstraintSet`。

1.  当选择每个密码时，添加`Transition`。

1.  通过转到“运行”菜单并点击“运行应用”菜单项来运行应用程序。

1.  输入一个长度，选择大写字母、数字和特殊字符，然后点击“生成”按钮。将显示三个密码。

1.  选择一个密码，其他密码将移出视图。还会显示一个“复制”按钮。点击它，检查你选择的密码是否现在在剪贴板上。输出屏幕的初始状态和最终状态将类似于*图 15.21*：

![图 15.21：密码生成器应用中 MotionLayout 的起始和结束状态](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_15_21.jpg)

图 15.21：密码生成器应用中 MotionLayout 的起始和结束状态

注意

此活动的解决方案可在以下网址找到：http://packt.live/3sKj1cp

# 总结

本章介绍了如何使用`CoordinatorLayout`和`MotionLayout`创建动画和过渡。动画可以提高应用的可用性，并使其与其他应用脱颖而出。

我们首先定制了打开和关闭活动时的过渡，使用了活动过渡。我们还了解了当一个活动和它打开的活动都包含相同的元素时，如何添加共享元素过渡，以便我们可以向用户突出显示这些共享元素之间的链接。

我们学习了如何使用`CoordinatorLayout`来处理其子视图的运动。一些视图具有内置的行为，用于处理它们在`CoordinatorLayout`中的工作方式。您也可以为其他视图添加自定义行为。然后，我们开始使用`MotionLayout`来创建动画，通过指定起始约束、结束约束和它们之间的过渡。我们还研究了通过在动画中间添加关键帧来修改运动路径。我们了解了关键帧，比如`KeyPosition`，它可以改变视图的位置，以及`KeyAttribute`，它可以改变视图的样式。我们还研究了在 Android Studio 中使用 Motion Editor 来简化动画的创建和预览以及修改路径。

在下一章中，我们将学习关于 Google Play 商店。我们将讨论如何创建帐户并准备您的应用发布，以及如何发布供用户下载和使用。


# 第十六章：在 Google Play 上发布您的应用程序

概述

本章将向您介绍 Google Play 控制台、发布渠道和整个发布流程。它涵盖了创建 Google Play 开发者帐户、为我们开发的应用程序设置商店条目以及创建密钥库（包括密码的重要性和文件存储位置）。我们还将了解应用程序包和 APK，以及如何生成应用程序的 APK 或 AAB 文件。在本章的后面部分，我们将设置发布路径、开放测试版和封闭测试版，最后我们将把我们的应用上传到商店并在设备上下载。

通过本章结束时，您将能够创建自己的 Google Play 开发者帐户，为发布准备已签名的 APK 或应用程序包，并在 Google Play 上发布您的第一个应用程序。

# 介绍

在上一章中，您学会了如何使用`CoordinatorLayout`和`MotionLayout`添加动画和过渡。现在，您已经准备好开发和发布 Android 应用程序。

开发 Android 应用程序后，它们只能在您的设备和模拟器上使用。您必须使它们对所有人都可用，以便他们可以下载。反过来，您将获得用户，并且可以从他们那里赚钱。Android 应用程序的官方市场是 Google Play。通过 Google Play，您发布的应用程序和游戏可以在全球超过 20 亿活跃的 Android 设备上使用。

在本章中，我们将学习如何在 Google Play 上发布您的应用程序。我们将从为发布准备应用程序和创建 Google Play 开发者帐户开始。然后，我们将继续上传您的应用程序并管理应用程序发布。

让我们开始准备在 Google Play 上发布您的应用程序。

# 为发布准备您的应用程序

在 Google Play 上发布应用程序之前，您必须确保它使用了发布密钥进行签名，并且具有正确的版本信息。否则，您将无法发布新应用程序或更新已发布的应用程序。

让我们从为您的应用程序添加版本开始。

## 应用程序版本

您的应用程序版本之所以重要，有以下几个原因：

+   用户可以看到他们已下载的版本。在检查是否有更新或报告应用程序的已知问题时，他们可以使用这个信息。

+   设备和 Google Play 使用版本值来确定应用程序是否可以或应该更新。

+   开发人员还可以使用这个值在特定版本中添加功能支持。他们还可以警告或强制用户升级到最新版本，以获得有关错误或安全问题的重要修复。

Android 应用程序有两个版本：`versionCode`和`versionName`。现在，`versionCode`是一个整数，由开发人员、Google Play 和 Android 系统使用，而`versionName`是一个字符串，用户在 Google Play 页面上看到的。

应用程序的初始发布可以将`versionCode`值设为`1`，每次新发布都应该增加这个值。

`versionName`可以采用*x.y*格式（其中*x*是主要版本，*y*是次要版本）。您还可以使用语义版本控制，如*x.y.z*，通过添加*z*来添加补丁版本。要了解更多关于语义版本控制的信息，请参阅[`semver.org`](https://semver.org)。

在模块的`build.gradle`文件中，在 Android Studio 中创建新项目时，`versionCode`和`versionName`会自动生成。它们位于`android`块下的`defaultConfig`块中。一个示例`build.gradle`文件显示了这些值：

```kt
android {
    compileSdkVersion 29
    defaultConfig {
        applicationId "com.example.app"
        minSdkVersion 16
        targetSdkVersion 29
        versionCode 1
        versionName "1.0"
        ...
    }
    ...
}
```

在发布更新时，要发布的新包必须具有更高的`versionCode`值，因为用户无法降级其应用程序，只能下载新版本。

在确保应用程序版本正确之后，发布流程的下一步是获取一个密钥库来对应用程序进行签名。这将在下一节中讨论。

## 创建密钥库

Android 应用程序在运行时会自动使用调试密钥进行签名。但是，在将应用程序发布到 Google Play 商店之前，必须使用发布密钥对应用程序进行签名。为此，您必须拥有一个密钥库。如果您还没有，可以在 Android Studio 中创建一个。

## 练习 16.01：在 Android Studio 中创建密钥库

在这个练习中，我们将使用 Android Studio 创建一个密钥库，用于签署 Android 应用程序。按照以下步骤完成这个练习：

1.  在 Android Studio 中打开一个项目。

1.  转到“构建”菜单，然后单击“生成已签名的捆绑包或 APK…”：![图 16.1：生成已签名的捆绑包或 APK 对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_01.jpg)

图 16.1：生成已签名的捆绑包或 APK 对话框

1.  确保选择了`APK`或“Android 应用程序捆绑包”，然后点击“下一步”按钮。在这里，您可以选择现有的密钥库或创建一个新的：![图 16.2：选择 APK 后点击“下一步”按钮后的生成已签名的捆绑包或 APK 对话框并点击“下一步”按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_02.jpg)

图 16.2：选择 APK 并点击“下一步”按钮后的生成已签名的捆绑包或 APK 对话框

1.  点击“创建新…”按钮。然后将出现“新密钥库”对话框：![图 16.3：新密钥库对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_03.jpg)

图 16.3：新密钥库对话框

1.  在“密钥库路径”字段中，选择要保存密钥库文件的位置。您可以点击右侧的文件夹图标选择文件夹并输入文件名。该值将类似于`users/packt/downloads/keystore.keystore`

1.  在“密码”和“确认”字段中提供密码。

1.  在“密钥”下的证书部分，输入名字、组织单位、组织、城市/地点、州/省和国家代码。这些信息中只有一个是必需的，但最好提供所有信息。

1.  点击“确定”按钮。如果没有错误，密钥库将在您提供的路径中创建，并且您将回到“生成已签名的捆绑包或 APK”对话框，以便继续生成 APK 或应用程序捆绑包。如果您只想创建一个密钥库，可以关闭对话框。

在这个练习中，您已经创建了自己的密钥库，可以用来签署可以发布到 Google Play 的应用程序。

如果您更喜欢使用命令行生成密钥库，也可以这样做。`keytool`命令在**Java 开发工具包**（**JDK**）中可用。命令如下：

```kt
keytool -genkey -v -keystore my-key.jks -keyalg RSA -keysize 
  2048 -validity 9125 -alias key-alias
```

此命令在当前工作目录中创建一个 2,048 位的 RSA 密钥库，文件名为`my-key.jks`，别名为`key-alias`；有效期为 9,125 天（25 年）。命令行将提示您输入密钥库密码，然后提示您再次确认。然后，它将要求您依次输入名字、组织单位、组织名称、城市或地点、州或省和国家代码。这些信息中只有一个是必需的；如果要留空，可以按“Enter”键。不过，最好提供所有信息。

在国家代码提示之后，将要求您验证提供的输入。您可以输入 yes 进行确认。然后将要求您提供密钥别名的密码。如果要与密钥库密码相同，可以按“Enter”。然后将生成密钥库。

现在您已经有了一个用于签署应用程序的密钥库，需要知道如何保护它。您将在下一节中了解到这一点。

## 存储密钥库和密码

您需要将密钥库和密码存放在安全的地方，因为如果您丢失了密钥库和/或其凭据，将无法再发布应用程序更新。如果黑客也能够访问这些内容，他们可能会未经您的同意更新您的应用程序。

您可以将密钥库存储在 CI/构建服务器或安全服务器中。

保留凭据有点棘手，因为在以后签署应用更新时，您将需要它们。您可以通过将此信息包含在项目的`build.gradle`文件中来实现这一点。

在`android`块中，您可以有`signingConfigs`，它引用密钥库文件、其密码以及密钥的别名和密码：

```kt
android {
    ...
    signingConfigs {
        release {
            storeFile file("keystore-file")
            storePassword "keystore-password"
            keyAlias "key-alias"
            keyPassword "key-password"
        }
    }
    ...
}
```

在项目的`build.gradle`文件中的`buildTypes`的发布块下，您可以在`signingConfigs`块中指定发布配置：

```kt
buildTypes {
        release {
            ...
            signingConfig signingConfigs.release
        }
        ...
}
```

将签名配置存储在`build.gradle`文件中并不安全，因为可以访问项目或存储库的人可能会 compromise the app。

您可以将这些凭据存储在环境变量中，以使其更安全。通过这种方法，即使恶意人士获得了对您代码的访问权限，应用更新仍将是安全的，因为签名配置并未存储在您的代码中，而是存储在系统中。环境变量是在 IDE 或项目之外设置的键值对，例如在您自己的计算机上或在构建服务器上。

要在 Gradle 中使用环境变量进行密钥库配置，您可以为存储文件路径、存储密码、密钥别名和密钥密码创建环境变量。例如，您可以使用`KEYSTORE_FILE`、`KEYSTORE_PASSWORD`、`KEY_ALIAS`和`KEY_PASSWORD`环境变量。

在 Mac 和 Linux 上，您可以使用以下命令设置环境变量：

```kt
export KEYSTORE_PASSWORD=securepassword
```

如果您使用 Windows，可以这样做：

```kt
set KEYSTORE_PASSWORD=securepassword
```

这个命令将创建一个名为`KEYSTORE_PASSWORD`的环境变量，其值为`securepassword`。在应用的`build.gradle`文件中，您可以使用环境变量中的值：

```kt
storeFile System.getenv("KEYSTORE_FILE")
storePassword System.getenv("KEYSTORE_PASSWORD")
keyAlias System.getenv("KEY_ALIAS")
keyPassword System.getenv("KEY_PASSWORD")
```

您的密钥库将用于为发布签署您的应用，以便您可以在 Google Play 上发布它。我们将在下一节中讨论这个问题。

## 为发布签署您的应用

当您在模拟器或实际设备上运行应用时，Android Studio 会自动使用调试密钥库对其进行签名。要在 Google Play 上发布应用，您必须使用您自己的密钥对 APK 或应用捆绑包进行签名，使用您在 Android Studio 中或通过命令行创建的密钥库。

如果您已经在`build.gradle`文件中为发布版本添加了签名配置，您可以通过在`Build Variants`窗口中选择发布版本构建自动构建已签名的 APK 或应用捆绑包。然后，您需要转到`Build`菜单，单击`Build Bundle(s)`项目，然后选择`Build APK(s)`或`Build Bundle(s)`。APK 或应用捆绑包将生成在项目的`app/build/output`目录中。

## 练习 16.02：创建已签名的 APK

在这个练习中，我们将使用 Android Studio 为 Android 项目创建一个已签名的 APK：

1.  在 Android Studio 中打开一个项目。

1.  转到`Build`菜单，然后单击`生成已签名的 Bundle 或 APK…`菜单项：![图 16.4：生成签名的 Bundle 或 APK 对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_04.jpg)

图 16.4：生成签名的 Bundle 或 APK 对话框

1.  选择`APK`，然后单击`下一步`按钮：![图 16.5：单击下一步按钮后的生成签名的 Bundle 或 APK 对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_05.jpg)

图 16.5：单击下一步按钮后的生成签名的 Bundle 或 APK 对话框。

1.  选择您在*练习 16.01*中创建的密钥库，*在 Android Studio 中创建密钥库*。

1.  在`Key store password`字段中提供密码。

1.  在`Key alias`字段中，单击右侧的图标并选择密钥别名。

1.  在`Key password`字段中提供别名密码。

1.  单击`下一步`按钮。

1.  选择生成已签名 APK 的目标文件夹。

1.  在`Build Variants`字段中，确保选择了`release`变体：![图 16.6：在生成签名的 Bundle 或 APK 对话框中选择发布版本](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_06.jpg)

图 16.6：在生成签名的 Bundle 或 APK 对话框中选择发布版本

1.  对于签名版本，请选择 V1 和 V2。 “V2（完整 APK 签名）”是一种整个文件方案，可以增加应用程序的安全性并使其安装速度更快。 这仅适用于 Android 7.0 Nougat 及更高版本。 如果您的目标低于此版本，还应使用“V1（Jar 签名）”，这是签署 APK 的旧方式，但安全性不及 v2。

1.  单击“完成”按钮。 Android Studio 将构建已签名的 APK。 IDE 通知将弹出，通知您已生成已签名的 APK。 您可以单击“定位”以转到已签名 APK 文件所在的目录：

![图 16.7：成功生成已签名 APK 的弹出通知](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_07.jpg)

图 16.7：成功生成已签名 APK 的弹出通知

在本练习中，您已经制作了一个已签名的 APK，现在可以在 Google Play 上发布。 在下一节中，您将了解 Android 应用捆绑包，这是一种发布应用的新方式。

## Android 应用捆绑包

发布 Android 应用的传统方式是通过 APK 或应用程序包。 当用户安装您的应用时，将下载此 APK 文件到他们的设备上。 这是一个包含所有设备配置的字符串、图像和其他资源的大文件。

随着您支持更多的设备类型和更多的国家/地区，此 APK 文件的大小将增长。 用户下载的 APK 将包含实际上对其设备不是必需的内容。 对于存储空间较小的用户，这将是一个问题，因为他们可能没有足够的空间来安装您的应用。 有昂贵数据计划或较慢的互联网连接的用户可能会避免下载太大的应用。 他们可能还会卸载您的应用以节省存储空间。

一些开发人员一直在构建和发布多个 APK 以避免这些问题。 但是，这是一个复杂且低效的解决方案，特别是当您针对不同的屏幕密度、CPU 架构和语言时。 这将是每个发布版本维护太多 APK 文件。

Android 应用捆绑包是发布应用的新方式。 您只需生成一个单个的应用程序捆绑包文件（使用 Android Studio 3.2 及更高版本），然后将其上传到 Google Play。 Google Play 将自动生成基本 APK 文件以及每个设备配置、CPU 架构和语言的 APK 文件。 当用户安装您的应用时，他们只会下载其设备所需的 APK 文件。 与通用 APK 相比，这将更小。

这将适用于 Android 5.0 棒棒糖及更高版本的设备； 对于低于此版本的设备，将仅生成设备配置和 CPU 架构的 APK 文件。 所有语言和其他资源将包含在每个 APK 文件中。

## 练习 16.03：创建已签名的应用程序捆绑包

在本练习中，我们将使用 Android Studio 为 Android 项目创建一个已签名的应用程序捆绑包：

1.  在 Android Studio 中打开一个项目。

1.  转到“构建”菜单，然后单击“生成签名捆绑包或 APK…”菜单项：![图 16.8：生成签名捆绑包或 APK 对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_08.jpg)

图 16.8：生成签名捆绑包或 APK 对话框

1.  选择“Android 应用捆绑包”，然后单击“下一步”按钮：![图 16.9：单击“下一步”按钮后生成签名捆绑包或 APK 对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_09.jpg)

图 16.9：单击“下一步”按钮后生成签名捆绑包或 APK 对话框

1.  选择您在*练习 16.01*中创建的密钥库，*在 Android Studio 中创建密钥库*。

1.  在“密钥库密码”字段中提供密码。

1.  在“密钥别名”字段中，单击右侧的图标并选择密钥别名。

1.  在“密钥密码”字段中提供别名密码。

1.  单击“下一步”按钮。

1.  选择生成已签名应用程序捆绑包的目标文件夹。

1.  在“构建变体”字段中，确保选择了“发布”变体：![图 16.10：在生成签名捆绑包或 APK 对话框中选择发布版本](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_10.jpg)

图 16.10：在生成已签名的应用程序包或 APK 对话框中选择发布版本

1.  单击`完成`按钮。Android Studio 将构建已签名的应用程序包。IDE 通知将弹出，通知您已生成已签名的应用程序包。您可以单击`定位`以转到已签名的应用程序包文件所在的目录：

![图 16.11：弹出通知，已生成已签名的应用程序包](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_11.jpg)

图 16.11：弹出通知，已生成已签名的应用程序包

在这个练习中，您已经制作了一个已签名的应用程序包，现在可以在 Google Play 上发布。

要能够以 Android 应用程序包格式发布您的应用程序，您需要选择通过 Google Play 进行应用签名。我们将在下一节讨论 Google Play 应用签名。

## Google Play 应用签名

Google Play 提供了一项名为应用签名的服务，允许 Google 管理和保护您的应用签名密钥，并为用户自动重新签名您的应用。

使用 Google Play 应用签名，您可以让 Google 生成签名密钥，也可以上传您自己的签名密钥。您还可以为了额外的安全性创建不同的上传密钥。您可以使用上传密钥对应用程序进行签名，并在 Play 控制台上发布应用程序。Google 将检查上传密钥，删除它，并使用应用签名密钥重新签名应用程序以分发给用户。当应用签名对应用程序启用时，可以重置上传密钥。如果您丢失了上传密钥或认为它已经被泄露，您可以简单地联系 Google Play 开发者支持，验证您的身份，并获得新的上传密钥。

在发布新应用程序时，选择应用签名是很容易的。在 Google Play 控制台([`play.google.com/console`](https://play.google.com/console))中，您可以转到`发布管理` | `应用发布`部分，并在`让 Google 管理和保护您的应用签名密钥`部分选择`继续`。您最初用于签署应用的密钥将成为上传密钥，Google Play 将生成新的应用签名密钥。

您还可以将现有的应用程序转换为使用应用签名。这在 Google Play 控制台中应用程序的`发布` | `设置` | `应用签名`部分中可用。您需要上传现有的应用签名密钥并生成新的上传密钥。

一旦您加入 Google Play 应用签名，您将无法再退出。此外，如果您使用第三方服务，您需要使用应用签名密钥的证书。这在`发布管理` | `应用签名`中可用。

应用签名还使您能够上传应用程序包，Google Play 将自动签名并生成用户在安装您的应用程序时将下载的 APK 文件。

在下一节中，您将创建一个 Google Play 开发者帐户，以便您可以将应用程序的已签名 APK 或应用程序包发布到 Google Play。

# 创建开发者帐户

要在 Google Play 上发布应用程序，您需要采取的第一步是创建一个 Google Play 开发者帐户。前往[`play.google.com/console/signup`](https://play.google.com/console/signup)并使用您的 Google 账户登录。如果您还没有 Google 账户，您应该首先创建一个。

建议使用长期计划使用的 Google 账户，而不是一次性账户。阅读开发者分发协议并同意服务条款。

注意

如果您的目标是销售付费应用程序或向您的应用程序/游戏添加应用内产品，您还必须创建一个商户账户。不幸的是，这并非所有国家都可以使用。我们在这里不会涉及这个问题，但您可以在注册页面或[`support.google.com/googleplay/android-developer/answer/150324`](https://support.google.com/googleplay/android-developer/answer/150324)上阅读更多信息。

您需要支付 25 美元的注册费用来创建您的 Google Play 开发者帐户（这是一次性付款）。该费用必须使用有效的借记卡/信用卡支付，但某些预付/虚拟信用卡也可以使用。您可以根据位置/国家使用的方式有所不同。

最后一步是完成帐户详细信息，如开发者名称、电子邮件地址、网站和电话号码。这些信息也可以稍后更新，将形成显示在您应用程序商店列表上的开发者信息。

完成注册后，您将收到一封确认电子邮件。您的付款可能需要几个小时（最多 48 小时）才能处理并注册您的帐户，所以请耐心等待。理想情况下，即使您的应用程序还没有准备好，也应提前进行此操作，以便一旦准备好发布，您就可以轻松地发布该应用程序。

当您收到来自 Google 的确认电子邮件时，您可以开始将应用程序和游戏发布到 Google Play。

在接下来的部分中，我们将讨论将应用程序上传到 Google Play。

# 上传应用程序到 Google Play

一旦您准备好发布应用程序并拥有 Google Play 开发者帐户，您可以转到 Google Play 控制台（[`play.google.com/console`](https://play.google.com/console)）发布应用程序。

要上传应用程序，请转到 Play 控制台，单击“所有应用程序”，然后单击“创建应用程序”。提供应用程序的名称和默认语言。在应用程序或游戏部分，设置它是应用程序还是游戏。同样，在免费或付费部分，设置它是免费还是付费。创建您的商店列表，准备应用程序发布，并推出发布。我们将在本节中详细介绍这些步骤。

## 创建商店列表

商店列表是用户在打开您的应用程序在 Google Play 上的页面时首先看到的内容。如果应用程序已经发布，您可以转到“增长”，然后选择“商店出现”，然后选择“主商店列表”。

### 应用详细信息

您将被导航到“应用详细信息”页面。在“应用详细信息”页面上，您需要填写以下字段：

+   `应用名称`：您的应用程序名称（最多 50 个字符）。

+   `简短描述`：总结您的应用程序的简短文本（最多 80 个字符）。

+   `完整描述`：您应用程序的长描述。限制为 4,000 个字符，因此您可以在此处添加大量相关信息，例如其功能和用户需要了解的内容。

注意

对于产品详细信息，您可以根据您将发布应用程序的语言/国家添加本地化版本。

您的应用程序标题和描述不得包含受版权保护的材料和垃圾邮件，因为这可能会导致您的应用程序被拒绝。

### 图形资产

在此部分提供以下详细信息：

+   图标（512 x 512 的高分辨率图标）。

+   特色图形（1,024 x 500）：

+   应用程序的 2-8 张屏幕截图。如果您的应用程序支持其他形式因素（平板电脑、电视或 Wear OS），您还应该为每种形式因素添加屏幕截图：

您还可以添加促销图形和促销视频，如果有的话。

如果您使用违反 Google Play 政策的图形，您的应用可能会被拒绝，因此请确保您使用的图像是您自己的，并且不包含受版权保护或不适当的内容。

## 准备发布

在准备发布之前，请确保您的构建已使用签名密钥签名。如果您要发布应用程序更新，请确保它与 Play 上当前版本代码更高的相同包名称、相同密钥签名。

您还必须确保遵循开发者政策（以避免任何违规行为），并确保您的应用程序符合应用程序质量指南。更多信息列在发布检查表上，您可以在[`support.google.com/googleplay/android-developer/`](https://support.google.com/googleplay/android-developer/)上查看。

### APK/应用程序包

您可以上传 APK（Android 包）或更新的格式：Android 应用程序包。转到“发布”，然后转到“应用发布”。这将显示每个跟踪中活动和草稿发布的摘要。

有不同的跟踪可以发布应用程序：

+   生产

+   开放测试

+   封闭测试

+   内部测试

我们将在本章的“管理应用发布”部分详细讨论发布跟踪。

选择要创建发布的跟踪。对于生产跟踪，您可以在左侧选择“管理”。对于其他跟踪，请先单击“测试”，然后选择跟踪。要在封闭测试跟踪上发布，您还必须选择“管理跟踪”，然后通过单击“创建跟踪”来创建新的跟踪。

完成后，您可以在页面右上角单击“创建新发布”。在“要添加的 Android 应用程序包和 APK”部分，您可以上传您的 APK 或应用程序包。

确保应用程序包或 APK 文件由您的发布签名密钥签名。如果没有正确签名，Google Play 控制台将不接受它。如果您要发布更新，则应用程序包或 APK 的版本代码必须高于现有版本。

您还可以添加发布名称和发布说明。发布名称是开发人员用来跟踪发布的，不会对用户可见。默认情况下，上传的 APK 或应用程序包的版本名称将设置为发布名称。发布说明形成了将显示在 Play 页面上的文本，并将通知用户应用程序的更新内容。

发布说明的文本必须添加在语言标签内。例如，默认的美国英语语言的开放和闭合标签分别为<en-US>和</en-US>。如果您的应用支持多种语言，则默认情况下每种语言标签都将显示在发布说明字段中。然后，您可以为每种语言添加发布说明。

如果您已经发布了应用程序，可以通过单击“从以前的发布复制”按钮并从列表中进行选择来复制以前发布的发布说明并重用或修改它们。

单击“保存”按钮后，发布将被保存，您可以随后返回。单击“审核发布”按钮将带您到屏幕，您可以在其中审核和发布发布。

## 发布发布

如果您准备发布您的发布，请转到 Play 控制台并选择您的应用。转到“发布”并选择您的发布跟踪。单击发布选项卡，然后单击发布旁边的“编辑”按钮：

![图 16.12：生产跟踪上的草稿发布](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_12.jpg)

图 16.12：生产跟踪上的草稿发布

您可以查看 APK 或应用程序包、发布名称和发布说明。单击“审核发布”按钮开始发布。Play 控制台将打开“审核和发布”屏幕。在这里，您可以查看发布信息，并检查是否有警告和错误。

如果您正在更新应用程序，还可以在创建另一个发布时选择发布百分比。将其设置为 100%表示所有用户都可以下载。当您将其设置为较低的百分比，例如 50%，则发布将对一半现有用户可用。

如果您对发布有信心，可以在页面底部选择“开始发布到生产”按钮。发布应用后，需要一段时间（新应用可能需要 7 天或更长时间）进行审核。您可以在 Google Play 控制台的右上角看到状态。这些状态包括以下内容：

+   待发布（您的新应用正在审核中）

+   已发布（您的应用现在可以在 Google Play 上使用）

+   拒绝（您的应用因违反政策而未发布）

+   暂停（您的应用违反了 Google Play 政策并被暂停）

如果您的应用程序存在问题，您可以解决问题并重新提交应用程序。您的应用程序可能因侵犯版权、冒充和垃圾邮件等原因而被拒绝。

应用程序发布后，用户现在可以下载它。新应用程序或应用程序更新在 Google Play 上变为可用之前可能需要一些时间。如果您试图在 Google Play 上搜索您的应用程序，可能无法搜索到。确保将其发布到生产或公开轨道上。

# 管理应用发布

您可以在不同轨道上逐步发布应用程序，以便在向公众推出之前对其进行测试。您还可以进行定时发布，使应用程序在特定日期可用，而不是在获得 Google 批准后自动发布。

## 发布轨道

在为应用程序创建发布时，您可以在四个不同的轨道之间进行选择：

+   生产是每个人都可以看到应用程序的地方。

+   公开测试是针对更广泛的公开测试。发布将在 Google Play 上可用，任何人都可以加入测试计划并进行测试。

+   封闭测试是为测试预发布版本的小群用户而设计的。

+   内部测试是用于开发/测试应用程序时的开发者/测试人员构建。

内部、封闭和公开轨道允许开发人员创建特殊发布，并允许真实用户下载，而其他用户则使用生产版本。这将使您能够快速了解发布是否存在错误，并在将其推出给所有人之前快速修复。这些轨道上的用户反馈也不会影响您应用程序的公共评论/评分。

理想的方式是在开发和内部测试期间首先在内部轨道上发布。当预发布版本准备就绪时，您可以为一小群受信任的人/用户/测试人员创建封闭测试。然后，您可以创建一个公开测试，让其他用户在完全发布之前尝试您的应用程序。

要进入每个轨道并管理发布，您可以转到 Google Play 控制台的“发布”部分，然后选择“生产”或“测试”，然后选择公开、封闭或内部轨道。

### 反馈渠道和选择加入链接

在内部、封闭和公开轨道上，有一个“反馈 URL 或电子邮件地址”和“测试人员如何加入您的测试”的部分。您可以在“反馈 URL 或电子邮件地址”中提供一个电子邮件地址或网站，测试人员可以在加入测试计划时发送反馈。当他们选择加入您的测试计划时，这将显示出来。

在“测试人员加入您的测试”部分，您可以复制链接与测试人员分享。然后他们可以使用此链接加入测试程序。

### 内部测试

此轨道用于开发/测试应用程序时的构建。在此处发布的版本将很快在 Google Play 上供内部测试人员使用。在“测试人员”选项卡中，有一个测试人员部分。您可以选择现有列表或创建新列表。内部测试最多可有 100 名测试人员。

### 封闭测试

在“测试人员”选项卡中，您可以为测试人员选择电子邮件列表或 Google Groups。如果选择电子邮件列表，请选择测试人员列表或创建新列表。封闭测试最多可有 2,000 名测试人员：

如果您选择 Google Groups，您可以提供 Google Group 的电子邮件地址（例如，`the-alpha-group@googlegroups.com`），该组的所有成员将成为测试人员：

### 公开测试

在“测试人员”选项卡中，您可以为测试人员设置“无限”或“有限数量”。有限测试的最小测试人员数量为 1,000 人：

在公开、封闭和内部轨道中，您可以添加用户作为您应用程序的测试人员。您将在下一节学习如何添加测试人员。

## 分阶段发布

在推出应用程序更新时，您可以首先将其发布给一小部分用户。如果发布存在问题，您可以停止发布或发布另一个更新来修复问题。如果没有问题，您可以逐渐增加发布百分比。这被称为**分阶段发布**。

如果您已向少于 100%的用户发布了更新，您可以转到 Play 控制台，选择“发布”，单击轨道，然后选择“发布”选项卡。在您想要更新的发布下方，您可以看到“管理推出”下拉菜单。它将有更新或停止推出的选项。

您可以选择“管理推出”，然后选择“更新推出”以增加发布的推出百分比。将出现一个对话框，您可以在其中输入推出百分比。您可以单击“更新”按钮以更新百分比。

100%的推出将使发布对所有用户可用。低于该百分比意味着发布只对该百分比的用户可用。

如果在分阶段推出期间发现了重大错误或崩溃，您可以转到 Play 控制台，选择“发布”，单击轨道，然后选择“发布”选项卡。在您想要更新的发布下方，选择“管理推出”，然后选择“停止推出”。将出现一个带有附加信息的对话框。添加一个可选的注释，然后单击“停止”按钮进行确认：

![图 16.13：停止分阶段推出的对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_13.jpg)

图 16.13：停止分阶段推出的对话框

当分阶段推出被停止时，您的轨道页面中的发布页面将更新为“推出已停止”文本和“恢复推出”按钮：

![图 16.14：停止分阶段推出的发布页面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_14.jpg)

图 16.14：停止分阶段推出的发布页面

如果您已解决了问题，例如在后端，而且没有必要发布新的更新，您可以恢复分阶段推出。要做到这一点，转到 Play 控制台，选择“发布”，单击轨道，然后选择“发布”选项卡。选择发布并单击“恢复推出”按钮。在“恢复分阶段推出”对话框中，您可以更新百分比，然后单击“恢复推出”以继续推出。

## 托管发布

在 Google Play 上推出新版本后，将在几分钟内发布。您可以将其更改为在以后的时间发布。当您针对特定日期时，例如与 iOS/web 发布的同一天或在发布日期之后，这将非常有用。

在创建和发布您想要控制发布的更新之前，必须设置托管发布。当您在 Google Play 控制台上选择您的应用时，您可以在左侧选择“发布概述”。在“托管发布状态”部分，单击“管理”按钮：

![图 16.15：发布概述上的托管发布](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_15.jpg)

图 16.15：发布概述上的托管发布

将显示托管发布状态。在这里，您可以打开或关闭托管发布，然后单击“保存”按钮。

当您打开“托管发布”时，您可以继续添加和提交应用的更新。您可以在“发布概述”中的“审查更改”部分看到这些更改：

一旦更改得到批准，“审查更改”将为空，并将移至“准备发布的更改”部分。在那里，您可以单击“审查和发布”按钮。在出现的对话框中，您可以单击“发布”按钮进行确认。然后您的更新将立即发布。

![图 16.16：托管发布准备发布的更改](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_16_16.jpg)

图 16.16：托管发布准备发布的更改

## 活动 16.01：发布应用

作为本书的最后一个活动，您的任务是创建一个 Google Play 开发者帐户，并发布您构建的新开发的 Android 应用程序。您可以发布本书的其中一个应用，或者您一直在开发的其他项目。您可以使用以下步骤作为指南：

1.  转到 Google Play 开发者控制台（[`play.google.com/console`](https://play.google.com/console)）并创建一个帐户。

1.  创建一个可用于签署发布版本的密钥库。

1.  为发布生成一个 Android 应用程序包。

1.  在将应用发布到生产轨道之前，可以将其发布到公开测试版轨道。

注意

本章已经详细解释了发布应用的步骤，因此针对这一活动没有单独的解决方案。您可以按照本章的练习成功完成前面的步骤。所需的确切步骤将是与您的应用独特相关的，并且将取决于您想要使用的设置。

# 总结

本章涵盖了 Google Play 商店：从准备发布、创建 Google Play 开发者帐户，到最终发布您的应用。我们从为您的应用版本化开始，生成密钥库，创建 APK 文件或 Android 应用捆绑包，并使用发布密钥库对其进行签名，以及存储密钥库及其凭据。然后我们转向在 Google Play 控制台上注册帐户，上传您的 APK 文件或应用捆绑包，并管理发布。

这是本书贯穿始终的工作的最终成果——发布您的应用并向世界开放，这是一个伟大的成就，也证明了您在本课程中取得的进步。

在本书中，您已经掌握了许多技能，从 Android 应用程序开发的基础开始，逐步实现诸如`RecyclerViews`、从 Web 服务获取数据、通知和测试等功能。您已经了解了如何通过最佳实践、架构模式和动画来改进您的应用，最后，您已经学会了如何将其发布到 Google Play。

这只是您作为 Android 开发人员旅程的开始。随着您继续构建更复杂的应用程序并扩展您在这里学到的知识，您还有许多更高级的技能需要发展。请记住，Android 在不断发展，因此及时了解最新的 Android 发布情况是很重要的。您可以访问[`developer.android.com/`](https://developer.android.com/)查找最新资源，并进一步沉浸在 Android 世界中。
