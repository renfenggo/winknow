using Winknow.ControlService;
using Winknow.Core;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = Constants.Services.Control;
});
builder.Services.AddHostedService<Worker>();

IHost host = builder.Build();
host.Run();
