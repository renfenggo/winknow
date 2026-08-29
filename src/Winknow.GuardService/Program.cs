using Winknow.GuardService;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Winknow Guard Service";
});
builder.Services.AddHostedService<Worker>();

IHost host = builder.Build();
host.Run();
