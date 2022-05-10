import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import lombok.Data;

import java.util.List;

@Data
public class DataSet {

    @JacksonXmlProperty(isAttribute = true)
    private String datasetName;
    @JacksonXmlProperty(isAttribute = true)
    private String iface;
    @JacksonXmlProperty(isAttribute = true)
    private String macSource;
    @JacksonXmlProperty(isAttribute = true)
    private String macDestination;
    @JacksonXmlProperty(isAttribute = true)
    private String goCbRef;
    @JacksonXmlProperty(isAttribute = true)
    private String goID;

    @JacksonXmlProperty(localName = "item")
    @JacksonXmlElementWrapper(useWrapping = false)
    private List<Item> items;

}
