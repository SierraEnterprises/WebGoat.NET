using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Data;
using OWASP.WebGoat.NET.App_Code.DB;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET
{
	public partial class SQLInjection : System.Web.UI.Page
	{
    
        private IDbProvider du = Settings.CurrentDbProvider;
        
		protected void Page_Load (object sender, EventArgs e)
		{

		}

		protected void btnFind_Click(object sender, EventArgs e)
        {
            string name = txtName.Text;
            DataSet ds = du.GetEmailByName(name);

            if (ds != null)
            {
                grdEmail.DataSource = ds.Tables[0];
                grdEmail.DataBind();
            }
		}
	}
	
	
	// Add SQL Injection from https://github.com/SierraEnterprises/gray_hat_csharp_code/blob/master/ch2_sqli_fuzzer/Program.cs
	class MainClass
	{
		public static void Main(string[] args) {
			string[] requestLines = File.ReadAllLines (args [0]); 
			string[] parms = requestLines [requestLines.Length - 1].Split ('&'); 
			string host = string.Empty; 
			StringBuilder requestBuilder = new StringBuilder(); 
			foreach (string ln in requestLines) { 
				if (ln.StartsWith ("Host:")) 
					host = ln.Split (' ') [1].Replace ("\r", string.Empty); 
				requestBuilder.Append(ln + "\n"); 
			} 
			string request = requestBuilder.ToString() + "\r\n";
			IPEndPoint rhost = new IPEndPoint (IPAddress.Parse (host), 80); 
			foreach (string parm in parms) { 
				Socket sock = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp); 
				sock.Connect (rhost); 
				string val = parm.Split('=')[1]; 
				string req = request.Replace("=" + val, "=" + val + "'");
				byte[] reqBytes = Encoding.ASCII.GetBytes (req); 
				sock.Send (reqBytes); 
				string response = string.Empty; 
				byte[] buf = new byte[sock.ReceiveBufferSize]; 
				sock.Receive (buf); 
				response = Encoding.ASCII.GetString (buf); 
				if (response.Contains("error in your SQL syntax")) 
					Console.WriteLine("Parameter " + parm + " seems vulnerable to SQL injection with value: " + val + "'"); 

				sock.Close();
			}
		}
	}
	
}
