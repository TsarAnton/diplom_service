using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace AuthLogService
{
	public partial class AuthLogService : ServiceBase
	{
		public AuthLogService()
		{
			InitializeComponent();
			eventLog1 = new System.Diagnostics.EventLog();
			if(!System.Diagnostics.EventLog.SourceExists("AuthLogSource"))
			{
				System.Diagnostics.EventLog.CreateEventSource("AuthLogSource", "AuthLogLog");
			}
			eventLog1.Source = "AuthLogSource";
			eventLog1.Log = "AuthLogLog";
		}

		protected override void OnStart(string[] args)
		{
			eventLog1.WriteEntry("Service AuthLog started");
		}

		protected override void OnStop()
		{
			eventLog1.WriteEntry("Serive AuthLog stoped");
		}
	}
}
