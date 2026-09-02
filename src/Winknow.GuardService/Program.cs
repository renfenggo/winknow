using Winknow.Core;
using Winknow.GuardService;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    // SCM 内部名：必须与安装器 sc create 的服务名一致（ADR-001/TD-01）
    options.ServiceName = ServiceNames.GuardService;
});
builder.Services.AddHostedService<Worker>();

IHost host = builder.Build();
host.Run();
