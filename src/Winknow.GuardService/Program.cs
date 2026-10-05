using Winknow.GuardService;
using Winknow.Core;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = Constants.Services.Guard;
});
builder.Services.AddHostedService<Worker>();

IHost host = builder.Build();
host.Run();
