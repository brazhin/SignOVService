using System.IO;
using System.Reflection;

namespace SignServiceTests
{
	internal static class Utils
	{
		public static byte[] GetStreamFromFile(string fileName)
		{
			var path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			var input = File.ReadAllBytes(Path.Combine(path, fileName));

			return input;
		}

		public static string GetTextFromFile(string fileName)
		{
			var path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
			var text = File.ReadAllText(Path.Combine(path, fileName));

			return text;
		}
	}
}
