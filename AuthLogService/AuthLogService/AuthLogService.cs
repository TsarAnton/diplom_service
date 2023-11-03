using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Runtime.Remoting.Messaging;

namespace AuthLogService
{
	//список состояний службы
	public enum ServiceState
	{
		SERVICE_STOPPED = 0x00000001,
		SERVICE_START_PENDING = 0x00000002,
		SERVICE_STOP_PENDING = 0x00000003,
		SERVICE_RUNNING = 0x00000004,
		SERVICE_CONTINUE_PENDING = 0x00000005,
		SERVICE_PAUSE_PENDING = 0x00000006,
		SERVICE_PAUSED = 0x00000007,
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct ServiceStatus
	{
		public int dwServiceType;
		public ServiceState dwCurrentState;
		public int dwControlsAccepted;
		public int dwWin32ExitCode;
		public int dwServiceSpecificExitCode;
		public int dwCheckPoint;
		public int dwWaitHint;
	};


	public partial class AuthLogService : ServiceBase
	{
		private AutoResetEvent signal;
		private string machineName;
		private string macAddress;
		private bool isLogon;
		private DateTime lastEventTime;

		//инициализация(выполняется 1 раз)
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
			//получаем mac адрес сетевой карты
			NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
			foreach (NetworkInterface ni in interfaces)
			{
				if (ni.Name.Equals("Ethernet"))
				{
					this.macAddress = ni.GetPhysicalAddress().ToString();
					break;
				}
			}
			eventLog1.Clear();
			//устанавливаем время запуска
			lastEventTime = DateTime.Now;
			isLogon = true;
		}

		//действия при старте службы
		protected override void OnStart(string[] args)
		{
			//обновление статуса на "начало запуска"
			ServiceStatus serviceStatus = new ServiceStatus();
			serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
			serviceStatus.dwWaitHint = 100000;
			SetServiceStatus(this.ServiceHandle, ref serviceStatus);
			eventLog1.WriteEntry("Service AuthLog started");

			signal = new AutoResetEvent(false);

			//получаем журнал безопасности
			EventLog securityLog = new EventLog("Security");

			//добавляем обработчик событий записи
			securityLog.EntryWritten += new EntryWrittenEventHandler(MyOnEntryWritten);
			securityLog.EnableRaisingEvents = true;
			bool firstSkip = false;
			if (firstSkip)
			{
				signal.WaitOne();
			}
			firstSkip = true;

			//обновление статуса на "запущена"
			serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
			SetServiceStatus(this.ServiceHandle, ref serviceStatus);
		}

		//при отключении службы
		protected override void OnStop()
		{
			//обновление статуса службы на "начало закрытия"
			ServiceStatus serviceStatus = new ServiceStatus();
			serviceStatus.dwCurrentState = ServiceState.SERVICE_STOP_PENDING;
			serviceStatus.dwWaitHint = 100000;
			SetServiceStatus(this.ServiceHandle, ref serviceStatus);

			//отправка на сервер выхода из учетки если сейчас isLogon ДОБАВИТЬ!!!!

			eventLog1.WriteEntry("Serive AuthLog stoped");
			//обновление статуса на "остановлена"
			serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
			SetServiceStatus(this.ServiceHandle, ref serviceStatus);
		}

		//действия при завершении работы
		protected override void OnShutdown()
		{
			//добавить отправку на сервер если сейчас isLogin ДОБАВИТЬ!!!!
			//base.OnShutdown();
		}

		//обработчик событий записи
		public void MyOnEntryWritten(object source, EntryWrittenEventArgs e)
		{
			//получаем добавленную запись
			EventLogEntry eventLogEntry = e.Entry;
			//сммотрим по id
			switch (eventLogEntry.InstanceId)
			{
				//если id события logon
				case 4624:
					//получаем тип входа, нам нужен 2
					if (GetType(eventLogEntry.Message) == 2)
					{
						//проверка на виртуальную учетную запись
						if (IsVirtual(eventLogEntry.Message))
						{
							//прверяем время последней записи (иногда он почему-то грузит журнал целиком или записи дублируются) чтобы запись заносилась только 1 раз
							if (eventLogEntry.TimeGenerated.CompareTo(lastEventTime) > 0)
							{
								isLogon = true;
								lastEventTime= eventLogEntry.TimeGenerated;
								this.machineName = eventLogEntry.MachineName;
								StringBuilder message2 = new StringBuilder();
								message2.Append("logon;").Append(eventLogEntry.TimeGenerated).Append(";").Append(macAddress).
									Append(";").Append(machineName).Append(";").Append(GetUserName(eventLogEntry.Message, true)).
									Append(";").Append(GetEnterId(eventLogEntry.Message, true));
								eventLog1.WriteEntry(message2.ToString());
							}
						}
					}
					break;
				//если id события logoff
				case 4647:
					if (eventLogEntry.TimeGenerated.CompareTo(lastEventTime) > 0)
					{
						isLogon = false;
						lastEventTime = eventLogEntry.TimeGenerated;
						StringBuilder message1 = new StringBuilder();
						message1.Append("logoff;").Append(eventLogEntry.TimeGenerated).Append(";").Append(macAddress).
									Append(";").Append(machineName).Append(";").Append(GetUserName(eventLogEntry.Message, false)).
									Append(";").Append(GetEnterId(eventLogEntry.Message, false));
						eventLog1.WriteEntry(message1.ToString());
					}
					break;
			}
			signal.Set();
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		private static extern bool SetServiceStatus(System.IntPtr handle, ref ServiceStatus serviceStatus);

		private int GetType(string message)
		{
			string[] messageArray = message.Split('\r');
			return Int32.Parse(messageArray[9].Split('\t')[3]);
		}

		private bool IsVirtual(string message)
		{
			string[] messageArray = message.Split('\r');
			return (messageArray[11].Split('\t')[3]).Equals("%%1843");
		}

		private string GetUserName(string message, bool type)
		{
			string[] messageArray = message.Split('\r');
			if (type)
			{
				return messageArray[18].Split('\t')[3];
			}
			return messageArray[4].Split('\t')[3];
		}

		private string GetEnterId(string message, bool type)
		{
			string[] messageArray = message.Split('\r');
			if (type)
			{
				return messageArray[20].Split('\t')[3];
			}
			return messageArray[6].Split('\t')[3];
		}
	}
}
