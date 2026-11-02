using Microsoft.Maui.LifecycleEvents;

namespace FileKeep.Reader.iOS;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
				fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
			})
			.ConfigureLifecycleEvents(events =>
			{
#if IOS
				// Slice 3: blank the app-switcher snapshot and wipe the DEK
				// the moment the app backgrounds.
				events.AddiOS(iOS => iOS
					.OnResignActive(app => Platforms.iOS.AppLifecycle.OnResignActive(app.Window))
					.OnActivated(app => Platforms.iOS.AppLifecycle.OnActivated()));
#endif
			});

		return builder.Build();
	}
}
