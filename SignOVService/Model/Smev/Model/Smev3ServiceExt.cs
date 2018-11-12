namespace SignOVService.Model.Smev.Model
{
	public partial class Request : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.RequestElement;
		}
	}

	public partial class Response : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.ResponseElement;
		}
	}

	public partial class Cancel : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.CancelElement;
		}
	}

	public partial class AttachmentHeaderList : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.AttachmentHeaderListElement;
		}
	}

	public partial class RefAttachmentHeaderList : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.RefAttachmentHeaderListElement;
		}
	}

	public partial class FSAttachmentsList : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.FSAttachmentsListElement;
		}
	}

	public partial class AttachmentContentList : ISmev3Element
	{
		public Smev3ElementType GetElementType()
		{
			return Smev3ElementType.AttachmentContentListElement;
		}
	}
}
