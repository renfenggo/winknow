using Winknow.ControlService;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Winknow Control Service";
});
builder.Services.AddHostedService<Worker>();

IHost host = builder.Build();
host.Run();
