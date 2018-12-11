using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace SignService.Smev.SmevTransform
{
	/// <summary>
	/// 
	/// </summary>
	public class SmevTransformAlg : Transform
	{
		public static readonly string ALGORITHM_URI = "urn://smev-gov-ru/xmldsig/transform";

		private Type[] allowInputTypes = new Type[] { typeof(XmlDocument), typeof(XmlNodeList), typeof(XmlNode), typeof(Stream), typeof(XmlReader) };

		private Type[] allowOutputTypes = new Type[] { typeof(XmlDocument), typeof(XmlNodeList), typeof(XmlNode), typeof(Stream), typeof(XmlReader) };

		private object innerObject;

		private XmlNodeList innerXml;

		private StringBuilder outputBuilder;

		private byte[] outputBytes;

		private MemoryStream outputMemoryStream;

		private XmlReader reader;

		private TransformObjectType typeInputObject = TransformObjectType.NotSet;

		private XmlWriter writer;

		/// <summary>
		/// 
		/// </summary>
		public SmevTransformAlg()
			: base()
		{
			Algorithm = ALGORITHM_URI;
		}

		/// <summary>
		/// 
		/// </summary>
		public override Type[] InputTypes
		{
			get { return allowInputTypes; }
		}

		/// <summary>
		/// 
		/// </summary>
		public override Type[] OutputTypes
		{
			get { return allowOutputTypes; }
		}

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		protected override XmlNodeList GetInnerXml()
		{
			return innerXml;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		public override object GetOutput()
		{
			return GetOutputObject(typeInputObject);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="type"></param>
		/// <returns></returns>
		public override object GetOutput(Type type)
		{
			TransformObjectType typeObj = TransformObjectType.NotSet;

			if (type.FullName == typeof(Stream).FullName)
			{
				typeObj = TransformObjectType.StreamType;
			}
			else if (type.FullName == typeof(XmlDocument).FullName)
			{
				typeObj = TransformObjectType.XmlDocumetType;
			}
			else if (type.FullName == typeof(XmlReader).FullName)
			{
				typeObj = TransformObjectType.XmlReaderType;
			}
			else if (type.FullName == typeof(XmlNodeList).FullName)
			{
				typeObj = TransformObjectType.XmlNodeListType;
			}
			else if (type.FullName == typeof(XmlNode).FullName)
			{
				typeObj = TransformObjectType.XmlNodeType;
			}
			else
			{
				typeObj = TransformObjectType.NotSet;
			}

			object result = GetOutputObject(typeObj);

			if (result == null)
			{
				result = innerObject;
			}

			return result;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="obj"></param>
		public override void LoadInput(object obj)
		{
			innerObject = obj;

			Type inputType = obj.GetType();

			Type xmlDocType = typeof(XmlDocument);
			Type streamType = typeof(Stream);
			Type xmlReaderType = typeof(XmlReader);
			Type xmlNodeListType = typeof(XmlNodeList);
			Type xmlNode = typeof(XmlNode);

			TransformObjectType loadInputType = TransformObjectType.NotSet;

			if (inputType == xmlDocType || inputType.IsSubclassOf(xmlDocType))
			{
				//logger.Debug("LoadInput for XmlDocument");
				loadInputType = TransformObjectType.XmlDocumetType;
			}
			else if (inputType == streamType || inputType.IsSubclassOf(streamType))
			{
				//logger.Debug("LoadInput for Stream");
				loadInputType = TransformObjectType.StreamType;
			}
			else if (inputType == xmlReaderType || inputType.IsSubclassOf(xmlReaderType))
			{
				//logger.Debug("LoadInput for XmlReader");
				loadInputType = TransformObjectType.XmlReaderType;
			}
			else if (inputType == xmlNodeListType || inputType.IsSubclassOf(xmlNodeListType))
			{
				//logger.Debug("LoadInput for XmlNodeList");
				loadInputType = TransformObjectType.XmlNodeListType;
			}
			else if (inputType == xmlNode || inputType.IsSubclassOf(xmlNode))
			{
				//logger.Debug("LoadInput for XmlNode");
				loadInputType = TransformObjectType.XmlNodeType;
			}

			LoadInputObject(obj, loadInputType);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="nodeList"></param>
		public override void LoadInnerXml(XmlNodeList nodeList)
		{
			SmevTransformAlg innerTransform = new SmevTransformAlg();
			innerTransform.LoadInput(nodeList);
			innerXml = innerTransform.GetOutput() as XmlNodeList;
		}

		/// <summary>
		/// 
		/// </summary>
		private void CreateWriter()
		{
			outputBuilder = new StringBuilder();

			XmlWriterSettings settings = new XmlWriterSettings
			{
				Indent = false,
				NamespaceHandling = NamespaceHandling.Default,
				NewLineOnAttributes = false,
				OmitXmlDeclaration = true,
				NewLineChars = "",
				NewLineHandling = NewLineHandling.Replace
			};

			writer = XmlWriter.Create(outputBuilder, settings);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="namespaceUri"></param>
		/// <returns></returns>
		private string GetNamespaceUri(string namespaceUri)
		{
			string value = namespaceUri;
			string result = string.Empty;

			foreach (char ch in value)
			{
				if (ch > 32)
				{
					result += ch;
				}
			}

			return result;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="argNamespaceURI"></param>
		/// <param name="argMappingStack"></param>
		/// <returns></returns>
		private XmlNamespaceWrap GetNamespaceWrap(string argNamespaceURI, Stack<List<XmlNamespaceWrap>> argMappingStack)
		{
			XmlNamespaceWrap result = null;

			for (int stackCounter = argMappingStack.Count - 1; stackCounter >= 0 && result == null; stackCounter--)
			{
				List<XmlNamespaceWrap> elementMappingList = argMappingStack.ElementAt(stackCounter);

				for (int elementCounter = 0; elementCounter < elementMappingList.Count && result == null; elementCounter++)
				{
					XmlNamespaceWrap mapping = elementMappingList[elementCounter];

					if (string.Compare(argNamespaceURI, mapping.NamespaceURI) == 0)
					{
						result = mapping;
					}
				}
			}

			return result;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="typeObj"></param>
		/// <returns></returns>
		private object GetOutputObject(TransformObjectType typeObj)
		{
			//logger.Debug("GetOutputObject");

			if (outputBuilder == null || string.IsNullOrEmpty(outputBuilder.ToString()))
			{
				//logger.Debug("GetOutputObject outputBuilder empty");

				if ((reader == null || reader.EOF) &&
					(this.Context != null) &&
					(string.IsNullOrEmpty(this.Context.OuterXml) == false))
				{
					//logger.Debug("GetOutputObject by Context");
					XmlNode node = (XmlNode)this.Context;
					if (string.IsNullOrEmpty(node.OuterXml) == false)
					{
						StringReader stringReader = new StringReader(node.OuterXml);
						reader = XmlReader.Create(stringReader, GetReaderSettings());
					}
				}

				Process();
			}

			object result = null;

			XmlDocument document = new XmlDocument();

			switch (typeObj)
			{
				case TransformObjectType.StreamType:

					//logger.Debug("GetOutputObject StreamType");
					if (outputMemoryStream != null)
					{
						try
						{
							//logger.Error("GetOutputObject close stream");
							outputMemoryStream.Close();
						}
						catch (Exception ex)
						{
							//logger.Error("GetOutputObject close stream error:" + ex.Message);
						}
					}

					if (outputBytes == null)
					{
						//logger.Error("GetOutputObject fill outputBytes");
						outputBytes = Encoding.UTF8.GetBytes(outputBuilder.ToString());
					}

					outputMemoryStream = new MemoryStream(outputBytes);
					result = outputMemoryStream;

					break;
				case TransformObjectType.XmlDocumetType:

					//logger.Debug("GetOutputObject XmlDocumetType");
					document.LoadXml(outputBuilder.ToString());
					result = document;

					break;
				case TransformObjectType.XmlNodeListType:

					//logger.Debug("GetOutputObject XmlNodeListType");

					if (outputBuilder != null && string.IsNullOrEmpty(outputBuilder.ToString()) == false)
					{
						document.LoadXml(outputBuilder.ToString());
					}

					result = document.ChildNodes;

					break;
				case TransformObjectType.XmlNodeType:

					//logger.Debug("GetOutputObject XmlNodeType");
					document.LoadXml(outputBuilder.ToString());
					result = document.DocumentElement as XmlNode;

					break;
				case TransformObjectType.XmlReaderType:

					//logger.Debug("GetOutputObject XmlReaderType");
					StringReader strReader = new StringReader(outputBuilder.ToString());
					result = XmlReader.Create(strReader, this.GetReaderSettings());

					break;
				default:
					//logger.Debug("GetOutputObject default");
					break;
			}

			return result;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		private XmlReaderSettings GetReaderSettings()
		{
			XmlReaderSettings settings = new XmlReaderSettings();
			settings.DtdProcessing = DtdProcessing.Parse;
			return settings;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="obj"></param>
		/// <param name="loadInputType"></param>
		private void LoadInputObject(object obj, TransformObjectType loadInputType)
		{
			reader = null;

			switch (loadInputType)
			{
				case TransformObjectType.StreamType:
					{
						typeInputObject = TransformObjectType.StreamType;
						Stream stream = (Stream)obj;

						if (stream != null && stream.Length > 0)
						{
							reader = XmlReader.Create(stream, GetReaderSettings());
						}

						break;
					}
				case TransformObjectType.XmlDocumetType:
					{
						typeInputObject = TransformObjectType.XmlDocumetType;
						XmlDocument doc = (XmlDocument)obj;

						if (string.IsNullOrEmpty(doc.OuterXml) == false)
						{
							StringReader stringReaderDoc = new StringReader(doc.OuterXml);
							reader = XmlReader.Create(stringReaderDoc, GetReaderSettings());
						}

						break;
					}
				case TransformObjectType.XmlNodeListType:
					{
						typeInputObject = TransformObjectType.XmlNodeListType;

						XmlNodeList list = (XmlNodeList)obj;
						StringBuilder builder = new StringBuilder();

						foreach (XmlNode tmpNode in list)
						{
							builder.Append(tmpNode.OuterXml);
						}

						if (!string.IsNullOrEmpty(builder.ToString()))
						{
							StringReader stringReaderList = new StringReader(builder.ToString());
							reader = XmlReader.Create(stringReaderList, GetReaderSettings());
						}

						break;
					}
				case TransformObjectType.XmlNodeType:
					{
						typeInputObject = TransformObjectType.XmlNodeType;
						XmlNode node = (XmlNode)obj;

						if (!string.IsNullOrEmpty(node.OuterXml))
						{
							StringReader stringReaderNode = new StringReader(node.OuterXml);
							reader = XmlReader.Create(stringReaderNode, GetReaderSettings());
						}

						break;
					}
				case TransformObjectType.XmlReaderType:
					{
						typeInputObject = TransformObjectType.XmlReaderType;
						reader = (XmlReader)obj;

						break;
					}
				default:
					{
						typeInputObject = TransformObjectType.NotSet;
						throw new NotImplementedException("Метод LoadInputObject вернул ошибку. Неизвестное значение TransformObjectType.");
					}
			}
		}

		/// <summary>
		/// 
		/// </summary>
		private void Process()
		{
			CreateWriter();

			if (reader != null)
			{
				Steps(reader);
			}
			else
			{
				//logger.Debug("Process reader empty");
			}
		}

		//TODO: refactoring
		private void Steps(XmlReader readerLoc)
		{

			Stack<List<XmlNamespaceWrap>> namespacesStack = new Stack<List<XmlNamespaceWrap>>();
			List<XmlNamespaceWrap> localNamespaces = new List<XmlNamespaceWrap>();
			List<XmlAttributeWrap> localAttributes = new List<XmlAttributeWrap>();
			int globalPrefixCounter = 1;

			// Parse the file.  
			while (readerLoc.Read())
			{
				if (readerLoc.NodeType == XmlNodeType.XmlDeclaration)
				{
				}
				else if (readerLoc.NodeType == XmlNodeType.Whitespace)
				{
				}
				else if (readerLoc.NodeType == XmlNodeType.ProcessingInstruction)
				{
				}
				else if (readerLoc.NodeType == XmlNodeType.Element)
				{
					if (readerLoc.IsStartElement())
					{
						localNamespaces = new List<XmlNamespaceWrap>();
						namespacesStack.Push(localNamespaces);

						localAttributes = new List<XmlAttributeWrap>();
						List<XmlNamespaceWrap> unusedNamespaces = new List<XmlNamespaceWrap>();

						XmlElementWrap startElement = new XmlElementWrap(readerLoc.Prefix, readerLoc.LocalName, GetNamespaceUri(readerLoc.NamespaceURI));
						for (int i = 0; i < readerLoc.AttributeCount; i++)
						{
							readerLoc.MoveToAttribute(i);

							// Namespace;
							if (string.Compare(readerLoc.Prefix, "xmlns", StringComparison.InvariantCultureIgnoreCase) == 0)
							{

							}
							else if (string.IsNullOrEmpty(readerLoc.Prefix) && string.Compare(readerLoc.LocalName, "xmlns", StringComparison.InvariantCultureIgnoreCase) == 0)
							{

							}
							else
							{
								XmlAttributeWrap att = new XmlAttributeWrap(readerLoc.Prefix, readerLoc.LocalName, readerLoc.NamespaceURI, readerLoc.Value);

								if (string.IsNullOrEmpty(readerLoc.NamespaceURI))
								{
									att.NamespaceURI = GetNamespaceUri(startElement.NamespaceURI);
								}

								localAttributes.Add(att);
							}

						}


						string elementNamespace = this.GetNamespaceUri(startElement.NamespaceURI);
						XmlNamespaceWrap elementPrefixNamespace = this.GetNamespaceWrap(elementNamespace, namespacesStack);
						string elementPrefix = elementPrefixNamespace != null ? elementPrefixNamespace.Prefix : string.Empty;

						if (string.IsNullOrEmpty(elementPrefix))
						{
							elementPrefix = "ns" + globalPrefixCounter;
							globalPrefixCounter++;

							localNamespaces.Add(new XmlNamespaceWrap(elementPrefix, elementNamespace));

							XmlAttributeWrap att = new XmlAttributeWrap("xmlns", elementPrefix, "http://www.w3.org/2000/xmlns/", elementNamespace);
							localAttributes.Add(att);
						}
						else
						{
							if (elementPrefixNamespace.Added == false)
							{
								elementPrefixNamespace.Added = true;

								XmlAttributeWrap att = new XmlAttributeWrap("xmlns", elementPrefix, "http://www.w3.org/2000/xmlns/", elementNamespace);
								localAttributes.Add(att);
							}
						}


						for (int k = 0; k < unusedNamespaces.Count; k++)
						{
							if (unusedNamespaces[k].NamespaceURI == elementNamespace)
							{
								unusedNamespaces.RemoveAt(k);
								break;
							}
						}

						writer.WriteStartElement(elementPrefix, startElement.LocalName, elementNamespace);

						List<XmlAttributeWrap> addAttrs = new List<XmlAttributeWrap>();


						AttributeSortingComparer comparatorPrev = new AttributeSortingComparer();
						localAttributes.Sort(comparatorPrev);

						foreach (XmlAttributeWrap tmpAtt in localAttributes)
						{
							if (string.Compare(tmpAtt.Prefix, "xmlns", StringComparison.InvariantCultureIgnoreCase) != 0)
							{

								string attributeNamespace = this.GetNamespaceUri(tmpAtt.NamespaceURI);
								//string attributePrefix = this.FindPrefix(attributeNamespace, namespacesStack);
								XmlNamespaceWrap attPrefixNamespace = this.GetNamespaceWrap(attributeNamespace, namespacesStack);
								string attributePrefix = (attPrefixNamespace != null) && (attPrefixNamespace.Prefix != null) ? attPrefixNamespace.Prefix : string.Empty;

								if (string.IsNullOrEmpty(attributePrefix))
								{
									attributePrefix = "ns" + globalPrefixCounter;
									globalPrefixCounter++;

									localNamespaces.Add(new XmlNamespaceWrap(attributePrefix, attributeNamespace));

									XmlAttributeWrap att = new XmlAttributeWrap("xmlns", attributePrefix, "http://www.w3.org/2000/xmlns/", attributeNamespace);
									addAttrs.Add(att);
								}
								else
								{
									if (attPrefixNamespace.Added == false)
									{
										attPrefixNamespace.Added = true;

										XmlAttributeWrap att = new XmlAttributeWrap("xmlns", attributePrefix, "http://www.w3.org/2000/xmlns/", attributeNamespace);
										localAttributes.Add(att);
									}
								}

								if (string.IsNullOrEmpty(tmpAtt.Prefix) == false)
								{
									tmpAtt.Prefix = attributePrefix;
								}

								tmpAtt.NamespaceURI = attributeNamespace;

								for (int k = 0; k < unusedNamespaces.Count; k++)
								{
									if (unusedNamespaces[k].NamespaceURI == attributeNamespace)
									{
										unusedNamespaces.RemoveAt(k);
										break;
									}
								}
							}
						}

						if (addAttrs.Count > 0)
						{
							localAttributes.AddRange(addAttrs);
						}

						if (unusedNamespaces.Count > 0)
						{
							List<string> forDelete = unusedNamespaces.Select(ns => ns.NamespaceURI).ToList();

							for (int k = localAttributes.Count - 1; k >= 0; k--)
							{
								if (forDelete.Contains(localAttributes[k].Value))
								{
									localAttributes.RemoveAt(k);
								}
							}

							for (int k = localNamespaces.Count - 1; k >= 0; k--)
							{
								if (forDelete.Contains(localNamespaces[k].NamespaceURI))
								{
									localNamespaces[k].Added = false;
								}
							}
						}

						AttributeSortingComparer comparator = new AttributeSortingComparer();
						localAttributes.Sort(comparator);
						localAttributes = comparator.SortXmlns(localAttributes, elementPrefix);

						foreach (XmlAttributeWrap tmpAtt in localAttributes)
						{
							if (string.IsNullOrEmpty(tmpAtt.Prefix))
							{
								writer.WriteAttributeString(tmpAtt.LocalName, tmpAtt.Value);
							}
							else
							{
								writer.WriteAttributeString(tmpAtt.Prefix, tmpAtt.LocalName, tmpAtt.NamespaceURI, tmpAtt.Value);
							}
						}
					}

				}
				else if (readerLoc.NodeType == XmlNodeType.EndElement)
				{
					namespacesStack.Pop();
					writer.WriteFullEndElement();
				}
				else if (readerLoc.NodeType == XmlNodeType.Attribute)
				{
					writer.WriteAttributeString(readerLoc.Prefix, readerLoc.LocalName, readerLoc.NamespaceURI, readerLoc.Value);

				}
				else if (readerLoc.NodeType == XmlNodeType.CDATA)
				{
					writer.WriteCData(readerLoc.Value);
				}
				else if (readerLoc.NodeType == XmlNodeType.Text)
				{
					writer.WriteString(readerLoc.Value);
				}

			}

			writer.Flush();
		}
	}
}
