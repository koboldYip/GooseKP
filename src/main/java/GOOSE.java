import lombok.Data;
import lombok.SneakyThrows;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

@Data
public class GOOSE implements Runnable {
    private byte[] destination = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] source = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private final byte[] type = {(byte) 0x88, (byte) 0xB8};

    private final byte[] appID = {0x00, 0x01};
    private final byte[] length = {0x00, 0x00};
    private final byte[] reserved1 = {0x00, 0x00};
    private final byte[] reserved2 = {0x00, 0x00};
    private final byte[] goosePdu = {0x61, (byte) 0x81, (byte) 0x8A};
    private final byte[] goCBRef = {(byte) 0x80, 0x00};
    private byte[] timeAllowedToLive = {(byte) 0x81, 0x05};
    private final byte[] datSet = {(byte) 0x82, 0x00};
    private final byte[] goID = {(byte) 0x83, 0x00};
    private final byte[] t = {(byte) 0x84, 0x08};
    private final byte[] stNum = {(byte) 0x85, 0x05};
    private final byte[] sqNum = {(byte) 0x86, 0x05};
    private final byte[] simulation = {(byte) 0x87, 0x01};
    private final byte[] confRev = {(byte) 0x88, 0x05};
    private final byte[] ndsCom = {(byte) 0x89, 0x01};
    private final byte[] numDatSetEntries = {(byte) 0x8A, 0x05};
    private final byte[] allDate = {(byte) 0xAB, 0x00};

    private final byte[] bool = {(byte) 0x83, 0x01};
    private final byte[] int32 = {(byte) 0x85, 0x05};
    private final byte[] float32 = {(byte) 0x87, 0x05};

    private byte[] valueGoCBRef;
    private byte[] valueDatSet;
    private byte[] valueGoID;

    private ByteBuffer valueStNum = ByteBuffer.allocate(5);
    private ByteBuffer valueSqNum = ByteBuffer.allocate(5);
    private boolean valueSimulation = false;
    private ByteBuffer valueConfRev = ByteBuffer.allocate(5);
    private boolean valueNdsCom = false;

    private byte[] valueBool = {0x01};
    private byte[] valueInt32 = {0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] valueFloat32 = {0x00, 0x00, 0x00, 0x00, 0x00};

    private ByteBuffer valueTimeAllowedToLive = ByteBuffer.allocate(5).put(new byte[]{0x00, 0x00, 0x00, 0x00, 0x06});
    private ByteBuffer valueT = ByteBuffer.allocate(8);
    private ByteBuffer valueNumDatSetEntries = ByteBuffer.allocate(5);

    private DataSet dataSet;

    private ByteBuffer buffer;
    private ByteBuffer headerBuffer;
    private ByteBuffer dataBuffer;

    private int[] delays = new int[]{0, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2000};
    private long startTime;
    private long previousTime;

    private int lenGoose;
    private int lenAllowTime;
    private int lenSq;
    private int lenData;
    private int lenT;
    private int lenSt;

    private boolean unPaused = true;

    private int conf;
    private int sq;
    private int st;

    private List<PcapNetworkInterface> ifs;
    private PcapHandle sendHandle;
    private EthernetPacket packet;

    @Override
    @SneakyThrows
    public void run() {
        sendHandle.sendPacket(packet);
        valueSqNum = valueSqNum.putInt(1, ++sq);
        valueTimeAllowedToLive = valueTimeAllowedToLive
                .putInt(1, (int) (delays[Math.min(sq + 1, delays.length - 1)] * 1.5));
        packet = EthernetPacket.newPacket(buffer.put(lenAllowTime, valueTimeAllowedToLive.array())
                .put(lenSq, valueSqNum.array()).array(), 0, lenGoose);
    }

    @SneakyThrows
    public GOOSE(DataSet dataSet) {
        ifs = Pcaps.findAllDevs();
        PcapNetworkInterface activeInterface = null;
        for (PcapNetworkInterface pcapIface : ifs) {
            if (pcapIface != null && pcapIface.getName().contains(dataSet.getIface())) {
                activeInterface = pcapIface;
                break;
            }
        }
        assert activeInterface != null;
        sendHandle = activeInterface.openLive(65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        this.dataSet = dataSet;
        createHeader(dataSet);
        createData(dataSet);
        createMessage();
    }

    @SneakyThrows
    private void createMessage() {
        valueT = valueT
                .putInt((int) (Instant.now().getEpochSecond()))
                .putInt(Instant.now().getNano());

        headerBuffer.put(destination)
                .put(source)
                .put(type)
                .put(appID)
                .put(length)
                .put(reserved1)
                .put(reserved2)
                .put(goosePdu)
                .put(goCBRef)
                .put(valueGoCBRef)
                .put(timeAllowedToLive)
                .put(valueTimeAllowedToLive.array())
                .put(datSet)
                .put(valueDatSet)
                .put(goID)
                .put(valueGoID)
                .put(t)
                .put(valueT.array())
                .put(stNum)
                .put(valueStNum.array())
                .put(sqNum)
                .put(valueSqNum.array())
                .put(simulation)
                .put(booleanToByte(valueSimulation))
                .put(confRev)
                .put(valueConfRev)
                .put(ndsCom)
                .put(booleanToByte(valueNdsCom))
                .put(numDatSetEntries)
                .put(valueNumDatSetEntries)
                .put(allDate);

        dataSet.getItems().forEach(this::typeValue);

        buffer.put(headerBuffer.array())
                .put(dataBuffer.array());

        packet = EthernetPacket.newPacket(buffer.array(), 0, lenGoose);
    }

    private void typeValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> dataBuffer.put(bool)
                    .put(booleanToByte(Boolean.valueOf(e.getValue())));

            case "Integer" -> dataBuffer.put(int32)
                    .put(new byte[]{0x00})
                    .putInt(Integer.parseInt(e.getValue()));

            case "Float" -> dataBuffer.put(float32)
                    .put(new byte[]{0x08})
                    .putFloat(Float.parseFloat(e.getValue()));

        }
    }

    private void createHeader(DataSet dataSet) {
        valueConfRev = valueConfRev.putInt(1, ++conf);
        valueStNum = valueStNum.putInt(1, ++st);
        valueDatSet = dataSet.getDatasetName().getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < destination.length; i++) {
            destination[i] = (byte) Integer.parseInt(dataSet.getMacDestination().split(":")[i], 16);
        }
        for (int i = 0; i < source.length; i++) {
            source[i] = (byte) Integer.parseInt(dataSet.getMacSource().split(":")[i], 16);
        }

        valueGoCBRef = dataSet.getGoCbRef().getBytes(StandardCharsets.UTF_8);
        valueGoID = dataSet.getGoID().getBytes(StandardCharsets.UTF_8);

        datSet[datSet.length - 1] = (byte) valueDatSet.length;
        goCBRef[goCBRef.length - 1] = (byte) valueGoCBRef.length;
        goID[goID.length - 1] = (byte) valueGoID.length;
    }

    private void createData(DataSet dataSet) {
        valueNumDatSetEntries = valueNumDatSetEntries.putInt(1, dataSet.getItems().size());

        lenAllowTime = destination.length +
                source.length +
                type.length +
                appID.length +
                length.length +
                reserved1.length +
                reserved2.length +
                goosePdu.length +
                goCBRef.length +
                valueGoCBRef.length +
                timeAllowedToLive.length;

        lenT = lenAllowTime +
                valueTimeAllowedToLive.array().length +
                datSet.length +
                valueDatSet.length +
                goID.length +
                valueGoID.length +
                t.length;

        lenSt = lenT +
                valueT.array().length +
                stNum.length;

        lenSq = lenSt +
                valueStNum.array().length +
                sqNum.length;

        lenData = lenSq +
                valueSqNum.array().length +
                simulation.length +
                booleanToByte(valueSimulation).length +
                confRev.length +
                valueConfRev.array().length +
                ndsCom.length +
                booleanToByte(valueNdsCom).length +
                numDatSetEntries.length +
                valueNumDatSetEntries.array().length +
                allDate.length;

        dataSet.getItems().forEach(this::lengthValue);

        dataBuffer = ByteBuffer.allocate(lenGoose);
        headerBuffer = ByteBuffer.allocate(lenData);

        lenGoose += lenData;

        buffer = ByteBuffer.allocate(lenGoose);

        length[length.length - 1] = (byte) (lenGoose - destination.length - source.length - type.length);
    }

    private void lengthValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> {
                lenGoose += bool.length + valueBool.length;
                allDate[allDate.length - 1] += bool.length + valueBool.length;
            }
            case "Integer" -> {
                lenGoose += int32.length + valueInt32.length;
                allDate[allDate.length - 1] += int32.length + valueInt32.length;
            }
            case "Float" -> {
                lenGoose += float32.length + valueFloat32.length;
                allDate[allDate.length - 1] += float32.length + valueFloat32.length;
            }
        }
    }

    private byte[] booleanToByte(Boolean bool) {
        if (bool) {
            return new byte[]{0x01};
        } else {
            return new byte[]{0x00};
        }
    }

    @SneakyThrows
    public void setData() {
        unPaused = false;
        sq = 0;

        dataBuffer.clear();
        dataSet.getItems().forEach(this::typeValue);

        valueSqNum = valueSqNum.putInt(1, sq);
        valueTimeAllowedToLive = valueTimeAllowedToLive
                .putInt(1, 6);
        valueStNum = valueStNum.putInt(1, ++st);

        valueT = valueT.clear()
                .putInt((int) (Instant.now().getEpochSecond()))
                .putInt(Instant.now().getNano());

        headerBuffer.put(lenAllowTime, valueTimeAllowedToLive.array())
                .put(lenSq, valueSqNum.array())
                .put(lenT, valueT.array())
                .put(lenSt, valueStNum.array());

        buffer.clear()
                .put(headerBuffer.array())
                .put(dataBuffer.array());

        packet = EthernetPacket.newPacket(buffer.array(), 0, lenGoose);
        unPaused = true;
    }


    public void send() {
        startTime = System.nanoTime();
        if (startTime - previousTime >= delays[Math.min(sq, delays.length - 1)] * 1000000L) {
            run();
            previousTime = startTime;
        }
    }
}
