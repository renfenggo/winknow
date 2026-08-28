using Winknow.GuardService;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Winknow Guard Service";
});
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
