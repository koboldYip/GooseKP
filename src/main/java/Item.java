import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Data;

@Data
public class Item {

    @JacksonXmlProperty(isAttribute = true)
    private String type;
    @JacksonXmlProperty(isAttribute = true)
    private String value;

}
