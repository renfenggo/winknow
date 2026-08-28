using Winknow.ControlService;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Winknow Control Service";
});
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
