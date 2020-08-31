
class MissingFieldData(Exception):
    """Custom exception to be called when a field needed to perfom
    an operation has no data.
    """
    pass

class MissingFieldSize(Exception):
    """Custom exception to be called when reading the fields from a
    OSNMA message and the field has no size in it.
    """
    pass